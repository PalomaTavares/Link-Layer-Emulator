from dccnet import DCCNet, SYNC, HEADER_FORMAT, HEADER_SIZE, MAX_PAYLOAD, TIMEOUT, MAX_RETRIES, ACK_FLAG, END_FLAG, RST_FLAG
import hashlib
import threading
import struct
import sys
import socket

class DCCNetClient(DCCNet):
    def __init__(self, host, port, gas):
        super().__init__(host, port, gas)
        self.text_buffer = ""
    
    def process_frame(self, frame):
        try:
            with self.processing_lock:
                if not self.validate_frame(frame):
                    return

                sync1, sync2, checksum, length, frame_id, flags = struct.unpack_from(
                    HEADER_FORMAT, frame, 0)
                payload = frame[HEADER_SIZE:HEADER_SIZE + length]

                print(f"Received valid frame - ID: {frame_id}, Flags: {flags:02x}, Length: {length}")

                if flags & RST_FLAG:
                    print("RST received - closing connection")
                    if payload:
                        try:
                            print(f"RST reason: {payload.decode().strip()}")
                        except UnicodeDecodeError:
                            print(f"RST with binary payload ({len(payload)} bytes)")
                    self.active = False
                    return

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
                                self._send_frame_internal(next_payload, next_flags, self.current_id)
                        else:
                            print(f"Unexpected or duplicate ACK received (ID={frame_id}, expecting={self.current_id}, waiting={self.waiting_ack})")
                    return

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
                                if char != "\n":  # Corrigido aqui
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

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(0.5)
            self.sock.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")

            retrans_thread = threading.Thread(target=self.retransmit_check, daemon=True)
            retrans_thread.start()

            self.send_frame(self.gas.encode())
            self.receive_loop()

        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.active = False
            if hasattr(self, 'sock') and self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass
            print("Connection closed")


def pad_sas_parts(input_str):
    # Split by '+'
    parts = input_str.split('+')
    
    # Last part is the token, keep it separate
    *sas_parts, token = parts
    
    padded_sas_parts = []
    for sas in sas_parts:
        elements = sas.split(':')
        if elements:
            # Pad the first element to 12 characters
            elements[0] = elements[0].ljust(12)
        padded_sas_parts.append(':'.join(elements))
    
    # Reconstruct full string with padded SAS parts and original token
    result = '+'.join(padded_sas_parts + [token])
    return result

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 dccnet-md5.py HOST:PORT GAS")
        sys.exit(1)

    try:
        host, port = sys.argv[1].split(":")
        gas = sys.argv[2]
        gas = pad_sas_parts(gas)

        DCCNetClient(host, int(port), gas).run()

    except ValueError:
        print("Invalid HOST:PORT format")
        sys.exit(1)
    except Exception as e:
        print(f"Startup error: {e}")
        sys.exit(1)