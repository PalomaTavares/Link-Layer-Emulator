import socket
import hashlib
import struct
import sys
import time
import threading
import signal

SYNC = 0xDCC023C2
HEADER_FORMAT = '!IIHHHB'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_PAYLOAD = 4096
TIMEOUT = 1
MAX_RETRIES = 16

ACK_FLAG = 0x80
END_FLAG = 0x40
RST_FLAG = 0x20

class DCCNetClient:
    def __init__(self, host, port, gas):
        self.host = host
        self.port = port
        self.gas = gas + "\n"
        self.sock = None
        self.buffer = b""
        self.text_buffer = ""
        self.current_id = 0
        self.last_received_id = None
        self.last_received_checksum = None
        self.last_frame = None
        self.send_queue = []
        self.last_sent_time = 0
        self.retries = 0
        self.active = True
        self.sending_lock = threading.Lock()
        self.processing_lock = threading.Lock()
        self.end_received = False
        self.waiting_ack = False
    
    def checksum(self, data):
        if len(data) % 2 == 1:
            data += b'\x00'
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) | data[i+1]
            total = (total & 0xffff) + (total >> 16)
        return ~total & 0xffff #o simbolo ~ inverte os bits de total

    #faz o setup do frame
    def build_frame(self, payload=b'', flags=0, frame_id=None):
        if frame_id is None:
            frame_id = self.current_id
        payload = payload[:MAX_PAYLOAD]
        header = struct.pack(HEADER_FORMAT, SYNC, SYNC, 0, len(payload), frame_id, flags)
        checksum = self.checksum(header + payload)
        header = struct.pack(HEADER_FORMAT, SYNC, SYNC, checksum, len(payload), frame_id, flags)
        return header + payload

    #faz o envio do frame
    def send_frame(self, payload=b'', flags=0, frame_id=None):
        try:
            with self.sending_lock: # Bloqueia o envio para evitar concorrência
                if frame_id is None:
                    frame_id = self.current_id
                frame = self.build_frame(payload, flags, frame_id)

                try:
                    if (flags & ACK_FLAG) or (flags & RST_FLAG) or (flags & END_FLAG):
                        self.sock.sendall(frame)
                        sync1, sync2, checksum, length, f_id, f_flags = struct.unpack_from(
                            HEADER_FORMAT, frame, 0)
                        print(f"Sent frame (ID={f_id}, Length={length}, Flags={f_flags:02x})")
                    else:
                        if self.waiting_ack:
                            print(f"Queuing frame (ID={frame_id}) - waiting for ACK")
                            self.send_queue.append((payload, flags, frame_id))
                        else:
                            self.sock.sendall(frame)
                            sync1, sync2, checksum, length, f_id, f_flags = struct.unpack_from(
                                HEADER_FORMAT, frame, 0)
                            print(f"Sent frame (ID={f_id}, Length={length}, Flags={f_flags:02x})")
                            #atualiza o estado da conexão:
                            self.last_frame = frame
                            self.last_sent_time = time.time()
                            self.retries = 0
                            self.waiting_ack = True
                except Exception as e:
                    print(f"Send error: {e}")
                    self.active = False
        except Exception as e:
            print(f"Send frame exception: {e}")

    def validate_frame(self, frame): #garante que o quadro cumpre todos os requisitos
        if len(frame) < HEADER_SIZE:
            print("Frame too short")
            return False

        try:
            sync1, sync2, checksum, length, frame_id, flags = struct.unpack_from(
                HEADER_FORMAT, frame, 0)

            if sync1 != SYNC or sync2 != SYNC:
                print("Invalid SYNC fields")
                return False

            if length > MAX_PAYLOAD:
                print(f"Payload too large: {length}")
                return False

            if len(frame) < HEADER_SIZE + length:
                print("Incomplete frame")
                return False

            frame_copy = bytearray(frame)
            frame_copy[8:10] = b'\x00\x00'
            if self.checksum(frame_copy) != checksum:
                print("Checksum mismatch")
                return False

            return True
        except Exception as e:
            print(f"Validation error: {e}")
            return False

    def process_frame(self, frame):
        try:
            with self.processing_lock:# Bloqueia o envio para evitar concorrência
                if not self.validate_frame(frame):
                    return

                sync1, sync2, checksum, length, frame_id, flags = struct.unpack_from(
                    HEADER_FORMAT, frame, 0)
                payload = frame[HEADER_SIZE:HEADER_SIZE + length]

                print(f"Received valid frame - ID: {frame_id}, Flags: {flags:02x}, Length: {length}")

                # lida com RST
                if flags & RST_FLAG:
                    print("RST received - closing connection")
                    if payload:
                        try:
                            print(f"RST reason: {payload.decode().strip()}")
                        except UnicodeDecodeError:
                            print(f"RST with binary payload ({len(payload)} bytes)")
                    self.active = False
                    return

                # Lida com quadro ACK
                if flags & ACK_FLAG:
                    with self.sending_lock:
                        print(f"Received ACK with ID={frame_id}, expecting ID={self.current_id}, waiting={self.waiting_ack}")
                        if self.waiting_ack and frame_id == self.current_id:
                            print(f"Valid ACK received for ID={frame_id}")
                            self.current_id = 1 - self.current_id
                            self.last_frame = None
                            self.waiting_ack = False
                            self.retries = 0

                            if self.send_queue:
                                next_payload, next_flags, next_id = self.send_queue.pop(0)
                                print(f"Sending queued frame (ID={self.current_id}, Flags={next_flags:02x})")
                                self.send_frame_internal(next_payload, next_flags, self.current_id)#envia o proximo da fila de imediato
                        else:
                            print(f"Unexpected or duplicate ACK received (ID={frame_id}, expecting={self.current_id}, waiting={self.waiting_ack})")
                    return

                # Frame de dados podendo terminar com a flag END
                is_end_frame = bool(flags & END_FLAG)
                if is_end_frame:
                    print("END flag received from server on data frame")
                    self.end_received = True

                frame_checksum = checksum
                is_duplicate = (self.last_received_id == frame_id and
                                self.last_received_checksum == frame_checksum)

                if frame_id != self.last_received_id or is_duplicate:
                    self.last_received_id = frame_id
                    self.last_received_checksum = frame_checksum

                    if not is_duplicate and payload:
                        try:
                            text = payload.decode('utf-8')
                            
                            print(f"\033[93mReceived text:\033[0m '{text.strip()}'")
                            
                            for char in text:
                                if char is not "\n":
                                    self.text_buffer += char
                                
                                else:
                                    
                                    md5_input = self.text_buffer.encode('utf-8')
                                    md5_hex = hashlib.md5(md5_input).hexdigest() + "\n"
                                    
                                    print(f"\033[31mMD5 input:\033[0m '{self.text_buffer}'")
                                    print(f"MD5 response: {md5_hex.strip()}")
                                    
                                    self.send_frame(md5_hex.encode('utf-8'))
                                    self.text_buffer = ""
                        except UnicodeDecodeError:
                            print(f"Binary data received ({len(payload)} bytes), sending ACK.")
                        except Exception as e:
                            print(f"Error processing payload: {e}")
                    elif is_duplicate:
                        print("Duplicate data frame detected, re-sending ACK.")

                    print(f"Sending ACK for data frame ID={frame_id}")
                    self.send_frame(b'', ACK_FLAG, frame_id)

                    if is_end_frame and not self.waiting_ack and not self.send_queue:
                        print("Processed frame with END flag, ACK sent, nothing pending. Closing.")
                        self.active = False
                        return
                else:
                    print(f"Unexpected data frame ID received: {frame_id}, expected: {1 - self.last_received_id if self.last_received_id is not None else 0}. Discarding.")
        except Exception as e:
            print(f"Process frame exception: {e}")
            self.active = False

    #envio de frame/quadro sem controle de fila
    def send_frame_internal(self, payload=b'', flags=0, frame_id=None):
        if frame_id is None:
            frame_id = self.current_id

        frame = self.build_frame(payload, flags, frame_id)

        try:
            self.sock.sendall(frame)
            sync1, sync2, checksum, length, f_id, f_flags = struct.unpack_from(
                HEADER_FORMAT, frame, 0)
            print(f"Sent frame (Internal - ID={f_id}, Length={length}, Flags={f_flags:02x})")

            if not (flags & ACK_FLAG) and not (flags & RST_FLAG):
                self.last_frame = frame
                self.last_sent_time = time.time()
                self.retries = 0
                self.waiting_ack = True
        except Exception as e:
            print(f"Internal send error: {e}")
            self.active = False

    #verifica se é necessario retransmitir e lida com retransmissap caso necessario
    def retransmit(self):
        while self.active:
            try:
                with self.sending_lock:#Bloqueia o envio para evitar concorrência
                    if self.waiting_ack and self.last_frame and time.time() - self.last_sent_time > TIMEOUT:#esperando ACK, existe last_frame enviado ou timeout
                        if self.retries < MAX_RETRIES:
                            try:
                                #reenvia ultimo frame
                                self.sock.sendall(self.last_frame)
                                self.retries += 1
                                self.last_sent_time = time.time()

                                sync1, sync2, checksum, length, frame_id, flags = struct.unpack_from(
                                    HEADER_FORMAT, self.last_frame, 0)
                                print(f"Retransmitting frame (ID={frame_id}, Length={length}, "
                                      f"Flags={flags:02x}, Attempt={self.retries}/{MAX_RETRIES})")
                            except Exception as e:
                                print(f"Retransmit error: {e}")
                                self.active = False
                        else:
                            print("Max retries reached - sending RST")
                            rst_frame = self.build_frame(b'Max retries exceeded', RST_FLAG, 0xFFFF)
                            try:
                                self.sock.sendall(rst_frame)
                            except Exception:
                                pass
                            self.active = False
            except Exception as e:
                print(f"Retransmission thread error: {e}")
            time.sleep(0.1)

    #entra em loop de recebimento
    def receive_loop(self):
        while self.active:
            try:
                data = self.sock.recv(4096)
                if not data:
                    print("Connection closed by server")
                    self.active = False
                    break

                self.buffer += data
                print(f"Received {len(data)} bytes, buffer now {len(self.buffer)} bytes")

                while self.active and len(self.buffer) >= HEADER_SIZE:
                    sync_pos = -1
                    for i in range(len(self.buffer) - 7):
                        if (struct.unpack_from('!I', self.buffer, i)[0] == SYNC and
                            struct.unpack_from('!I', self.buffer, i+4)[0] == SYNC):
                            sync_pos = i
                            break

                    if sync_pos == -1:
                        if len(self.buffer) > 8:
                            self.buffer = self.buffer[-8:]
                        break

                    if sync_pos > 0:
                        print(f"Discarding {sync_pos} bytes before SYNC")
                        self.buffer = self.buffer[sync_pos:]
                        sync_pos = 0

                    if len(self.buffer) < HEADER_SIZE:
                        break

                    length = struct.unpack_from('!H', self.buffer, 10)[0]
                    frame_end = HEADER_SIZE + length

                    if len(self.buffer) < frame_end:
                        break

                    frame = self.buffer[:frame_end]
                    self.buffer = self.buffer[frame_end:]
                    self.process_frame(frame)

            except socket.timeout:
                continue
            except Exception as e:
                print(f"Receive error: {e}")
                self.active = False

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(0.5)
            self.sock.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")

            retrans_thread = threading.Thread(target=self.retransmit, daemon=True)
            retrans_thread.start()

            self.send_frame(self.gas.encode())
            self.receive_loop()

        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"Error: {e}")
        finally:
            if self.active:
                self.active = False

            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass

            print("Connection closed")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 dccnet-md5.py HOST:PORT GAS")
        sys.exit(1)

    try:
        host, port = sys.argv[1].split(":")
        DCCNetClient(host, int(port), sys.argv[2]).run()

    except ValueError:
        print("Invalid HOST:PORT format")
        sys.exit(1)
    except Exception as e:
        print(f"Startup error: {e}")
        sys.exit(1)