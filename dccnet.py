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

class DCCNet:
    def __init__(self, host, port, gas="", sock=None, input=None, output=None):
        self.host = host
        self.port = port
        self.gas = gas + "\n"
        self.input = input
        self.output = output
        self.sock = sock
        self.buffer = b""
        self.current_id = 0             # ID para os frames de dados de saída
        self.last_received_id = None    # ID do último frame recebido
        self.last_received_checksum = None  # Checksum do último frame recebido
        self.last_frame = None          # Último frame enviado (para retransmissão)
        self.send_queue = []            # Fila de frames para envio
        self.last_sent_time = 0         # Timestamp do último envio
        self.retries = 0                # Contador de retentativas
        self.active = True              # Status da conexão (ativa/inativa)
        self.sending_lock = threading.Lock()  # Lock para operações de envio
        self.processing_lock = threading.Lock()  # Lock para processamento de frames
        self.end_received = False       # Flag indicando se recebeu frame com END
        self.waiting_ack = False    # Flag indicando se está aguardando ACK
        self.shutdown_in_progress = False  # Flag indicando desligamento em andamento

    def checksum(self, data):
        if len(data) % 2 == 1:
            data += b'\x00'
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) | data[i+1]
            total = (total & 0xffff) + (total >> 16)
        return ~total & 0xffff#o simbolo ~ inverte os bits de total

    #faz o setup do frame
    def build_frame(self, payload=b'', flags=0, frame_id=None):
        if frame_id is None:
            frame_id = self.current_id

        payload = payload[:MAX_PAYLOAD]

        # header com checksum 0
        header = struct.pack(HEADER_FORMAT, SYNC, SYNC, 0, len(payload), frame_id, flags)
        # calcula o checksum do frame
        checksum = self.checksum(header + payload)
        # refaz o header com o checksum calculado
        header = struct.pack(HEADER_FORMAT, SYNC, SYNC, checksum, len(payload), frame_id, flags)

        return header + payload

     #faz o envio do frame
    def send_frame(self, payload=b'', flags=0, frame_id=None):
        """Send a frame and store for retransmission if needed"""
        try:
            with self.sending_lock:# Bloqueia o envio para evitar concorrência
                # Usa current_id se frame_id nao especificado
                if frame_id is None:
                    frame_id = self.current_id
                frame = self.build_frame(payload, flags, frame_id)
                print(frame.hex())

                try:
                    # Se uma das flags ACK, RST or END, envia imediatamente, sem retransmissão
                    if (flags & ACK_FLAG) or (flags & RST_FLAG) or (flags & END_FLAG):
                        self.sock.sendall(frame)
                        sync1, sync2, checksum, length, f_id, f_flags = struct.unpack_from(
                            HEADER_FORMAT, frame, 0)
                        print(f"Sent frame (ID={f_id}, Length={length}, Flags={f_flags:02x})")
                    else:
                        # frames de daods:se esperando por ACK, adiciona a fila
                        if self.waiting_ack:
                            print(f"Queuing frame (ID={frame_id}) - waiting for ACK")
                            self.send_queue.append((payload, flags, frame_id))
                        else:
                            # envia quadro e espera o ACK
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

    #valida um frame recebido
    def validate_frame(self, frame):
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

            # verifica checksum
            frame_copy = bytearray(frame)
            frame_copy[8:10] = b'\x00\x00'
            if self.checksum(frame_copy) != checksum:
                print("Checksum mismatch")
                return False

            return True

        except Exception as e:
            print(f"Validation error: {e}")
            return False

    #processa um frame recebido
    def process_frame(self, frame):
        try:
            with self.processing_lock:
                if not self.validate_frame(frame):
                    return

                print(frame.hex())
                sync1, sync2, checksum, length, frame_id, flags = struct.unpack_from(
                    HEADER_FORMAT, frame, 0)
                payload = frame[HEADER_SIZE:HEADER_SIZE + length]

                print(f"Received valid frame - ID: {frame_id}, Flags: {flags:02x}, Length: {length}")

                # lida com termino imediato, devido a frame reset
                if flags & RST_FLAG:
                    print("RST received - closing connection")
                    if payload:
                        try:
                            print(f"RST reason: {payload.decode().strip()}")
                        except UnicodeDecodeError:
                            print(f"RST with binary payload ({len(payload)} bytes)")
                    self.active = False
                    return

                # lida com ACK
                if flags & ACK_FLAG:
                    with self.sending_lock:
                        print(f"Received ACK with ID={frame_id}, expecting ID={self.current_id}, waiting={self.waiting_ack}")
                        ack_processed = False
                        if self.waiting_ack and frame_id == self.current_id:
                            print(f"Valid ACK received for ID={frame_id}")
                            ack_processed = True
                            self.current_id = 1 - self.current_id
                            self.last_frame = None  # limpa frame para retransmissao
                            self.waiting_ack = False  # para de esperar por esse ACK especificamente
                            self.retries = 0 #zera tentativas

                            # Check 1: ACK para o client-initiated END?
                            if self.shutdown_in_progress:
                                print("ACK received for client-initiated END frame. Closing.")
                                self.active = False
                                return # Exit processing

                            # Check 2: END recebido, envio completado?
                            # lida com a competicao de corrida onde END vem antes do ACK.
                            if self.end_received and not self.send_queue:
                                print("END flag was previously received from server, and final ACK received. Closing.")
                                self.active = False
                                return

                            # se tem quadros na fila, envia o próximo
                            if self.send_queue:
                                next_payload, next_flags, next_id = self.send_queue.pop(0)
                                # nova current_id para o quadro/frame na fila
                                print(f"Sending queued frame (ID={self.current_id}, Flags={next_flags:02x})")
                                ##envia o proximo da fila de imediato
                                self._send_frame_internal(next_payload, next_flags, self.current_id)
                        else: #ACK inesperado
                            print(f"Unexpected or duplicate ACK received (ID={frame_id}, expecting={self.current_id}, waiting={self.waiting_ack})")
                            # nao muda o estado
                    return

                # processa flag END se estiver no frame de dados
                is_end_frame = bool(flags & END_FLAG)
                if is_end_frame:
                    print("END flag received from server on data frame")
                    self.end_received = True
                    # não termina a conexao imediatamente, envia ACK e garante que não está esperando por mais ACKs.

                # processa Payload
                frame_checksum = checksum
                is_duplicate = (self.last_received_id == frame_id and
                                self.last_received_checksum == frame_checksum)

                # aceita quasro se: nova ID ou duplicada da ultima recebida
                if frame_id != self.last_received_id or is_duplicate:
                    # guarda para identificar id duplicadas
                    self.last_received_id = frame_id
                    self.last_received_checksum = frame_checksum

                    #processa payload se novo frame
                    if not is_duplicate and payload:
                        try:
                            text = payload.decode('utf-8')
                            print(f"Received text: {text.strip()}")

                            if self.output:
                                with open(self.output, 'a') as f:
                                    f.write(text)

                        except UnicodeDecodeError:
                            print(f"Binary data received ({len(payload)} bytes), sending ACK.")
                        except Exception as e:
                            print(f"Error processing payload: {e}")
                    elif is_duplicate:
                        print("Duplicate data frame detected, re-sending ACK.")

                    # envia ACK usando a id do frame recebido
                    print(f"Sending ACK for data frame ID={frame_id}")
                    self.send_frame(b'', ACK_FLAG, frame_id)

                    # Final check: se o frame tinha flag END, ACK nao e esperado e fila vazia
                    if is_end_frame and not self.waiting_ack and not self.send_queue:
                         print("Processed frame with END flag, ACK sent, nothing pending. Closing.")
                         self.active = False
                         return

                else: # ID inesperada
                     print(f"Unexpected data frame ID received: {frame_id}, expected: {1 - self.last_received_id if self.last_received_id is not None else 0}. Discarding.")
                    
        except Exception as e:
            print(f"Process frame exception: {e}")
            self.active = False # Forca o fechamendo devido a exception no processamento

    #Envia assumindo lock
    def _send_frame_internal(self, payload=b'', flags=0, frame_id=None):
        if frame_id is None:
            frame_id = self.current_id

        frame = self.build_frame(payload, flags, frame_id)

        try:
            self.sock.sendall(frame)
            sync1, sync2, checksum, length, f_id, f_flags = struct.unpack_from(
                HEADER_FORMAT, frame, 0)
            print(f"Sent frame (Internal - ID={f_id}, Length={length}, Flags={f_flags:02x})")

            # se e quadro de dados guarda para retransmitir e seta flag de espera
            if not (flags & ACK_FLAG) and not (flags & RST_FLAG):
                self.last_frame = frame
                self.last_sent_time = time.time()
                self.retries = 0
                self.waiting_ack = True

        except Exception as e:
            print(f"Internal send error: {e}")
            self.active = False

    #lida com retransmissao
    def retransmit_check(self):
        while self.active:
            try:
                with self.sending_lock:
                    if self.waiting_ack and self.last_frame and time.time() - self.last_sent_time > TIMEOUT:
                        if self.retries < MAX_RETRIES:
                            try:
                                # retransmite o frame
                                self.sock.sendall(self.last_frame)
                                self.retries += 1
                                self.last_sent_time = time.time()

                                # printa detalhes do frame para debugar
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

    #loop de recebimento
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

                # processa frames completos
                while self.active and len(self.buffer) >= HEADER_SIZE:
                    # encontra dois valores consecutivos de SYNC
                    sync_pos = -1
                    for i in range(len(self.buffer) - 7):
                        if (struct.unpack_from('!I', self.buffer, i)[0] == SYNC and
                            struct.unpack_from('!I', self.buffer, i+4)[0] == SYNC):
                            sync_pos = i
                            break

                    if sync_pos == -1:
                        #sem SYNC consecutivo, mantes ultimos bytes para nova tentativa
                        if len(self.buffer) > 8:
                            self.buffer = self.buffer[-8:]
                        break

                    # descarta dados antes do sync
                    if sync_pos > 0:
                        print(f"Discarding {sync_pos} bytes before SYNC")
                        self.buffer = self.buffer[sync_pos:]
                        sync_pos = 0

                    # verifica se dados o suficiente
                    if len(self.buffer) < HEADER_SIZE:
                        break

                    # pega o tamanho do frame pelo header
                    length = struct.unpack_from('!H', self.buffer, 10)[0]
                    frame_end = HEADER_SIZE + length

                    # algum frame completo?
                    if len(self.buffer) < frame_end:
                        break

                    # extrai o frame e remove do buffer
                    frame = self.buffer[:frame_end]
                    self.buffer = self.buffer[frame_end:]

                    # processa o quadro
                    self.process_frame(frame)

            except socket.timeout:
                continue
            except Exception as e:
                print(f"Receive error: {e}")
                self.active = False

    def send_end_frame(self):
        if self.shutdown_in_progress:
            return

        self.shutdown_in_progress = True
        print("Sending END frame")

        try:
            if self.sending_lock.acquire(timeout=1):
                try:
                    if self.waiting_ack:
                        print("Still waiting for ACK, queueing END frame")
                        self.send_queue.append((b'', END_FLAG, self.current_id))
                    else:
                        end_frame = self.build_frame(b'', END_FLAG)
                        self.sock.sendall(end_frame)
                        sync1, sync2, checksum, length, f_id, f_flags = struct.unpack_from(
                            HEADER_FORMAT, end_frame, 0)
                        print(f"Sent END frame (ID={f_id}, Length={length}, Flags={f_flags:02x})")

                        #atualiza o estado para retransmissao:
                        self.last_frame = end_frame
                        self.last_sent_time = time.time()
                        self.retries = 0
                        self.waiting_ack = True

                finally:
                    self.sending_lock.release()
            else:
                print("Could not acquire lock for END frame, sending RST instead")
                self.send_rst_frame("Client shutdown - lock timeout")
        except Exception as e:
            print(f"Error sending END frame: {e}")
            self.send_rst_frame("Client shutdown - error")

    #Envia RST frame para fechar a conexao imediatamente
    def send_rst_frame(self, reason="Client shutdown"):
        try:
            rst_frame = self.build_frame(reason.encode(), RST_FLAG, 0xFFFF)
            self.sock.sendall(rst_frame)
            print(f"Sent RST frame: {reason}")
        except Exception as e:
            print(f"Error sending RST frame: {e}")
        finally:
            self.active = False
    #lida com interrupcoes
    def signal_handler(self, sig, frame):
        print("\nUser interrupt - initiating graceful shutdown")
        
        # tenta enviar END para fechar conexao
        if self.active and not self.shutdown_in_progress:
            self.send_end_frame()
            
            # espera END e o ACK serem processados
            timeout = time.time() + 5  # 5 segundos para timeout
            while self.active and time.time() < timeout:
                time.sleep(0.2)
                
            # se ativo pos timeout, forca fechar a conexao RST
            if self.active:
                print("Graceful shutdown timed out, sending RST")
                self.send_rst_frame("Client shutdown - timeout")
                
        sys.exit(0)

    def send_file(self):
        with open(self.input, 'r') as file:
            while self.active:
                if not self.waiting_ack:
                    line = file.readline()
                    if line:
                        self.send_frame(payload=line.encode())
                    else:
                        self.send_end_frame()
                        break

                time.sleep(0.1)



    def run(self):
        try:
            # configura o signal para fechar conexao
            signal.signal(signal.SIGINT, self.signal_handler)
            
            # inicia retransmissao
            retrans_thread = threading.Thread(target=self.retransmit_check, daemon=True)
            retrans_thread.start()

            if self.input:
                send_file_thread = threading.Thread(target=self.send_file, daemon=True)
                send_file_thread.start()

            # recebe loop
            self.receive_loop()

        except KeyboardInterrupt:
            # capturado pelo signal handler
            pass
        except Exception as e:
            print(f"Error: {e}")
        finally:
            #shutdown
            if self.active:
                self.active = False

            if self.sock:
                try:
                    # envia RST se a conexao foi fechada abruptamente
                    if not self.end_received and not self.shutdown_in_progress:
                        self.send_rst_frame("Client shutdown - cleanup")
                except Exception:
                    pass

                try:
                    self.sock.close()
                except Exception:
                    pass

            print("Connection closed")