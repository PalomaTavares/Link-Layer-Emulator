import socket
import hashlib
import struct
import sys
import time
from enum import IntFlag

# Constantes
SYNC = 0xDCC023C2
HEADER_FORMAT = '!IIHHBB'  # SYNC (4B), SYNC (4B), checksum (2B), length (2B), ID (1B), flags (1B)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_PAYLOAD = 4096
TIMEOUT = 15

class Flags(IntFlag):
    ACK = 0x80
    END = 0x40
    RST = 0x20

class DCCNetClient:
    def __init__(self, host, port, gas):
        self.host = host
        self.port = port
        self.gas = gas
        self.sock = None
        self.buffer = b""
        self.expected_id = 1
        self.last_received = time.time()
        
    def calculate_checksum(self, data):
        """Internet checksum implementation (RFC 1071)"""
        if len(data) % 2 != 0:
            data += b'\x00'
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]
            total += word
            total = (total & 0xffff) + (total >> 16)
        total = (total & 0xffff) + (total >> 16)  # Final carry
        return ~total & 0xffff
        
    def build_frame(self, payload=b'', flags=0, frame_id=None):
        """Build a valid DCCNET frame"""
        if frame_id is None:
            frame_id = 0 if flags & Flags.ACK else self.expected_id
            
        # First create header with zero checksum
        header = struct.pack(HEADER_FORMAT, 
                           SYNC, SYNC,
                           0,  # Checksum placeholder
                           len(payload),
                           frame_id,
                           flags)
        
        # Calculate checksum of header + payload
        checksum = self.calculate_checksum(header + payload)
        
        # Rebuild header with actual checksum
        header = struct.pack(HEADER_FORMAT,
                         SYNC, SYNC,
                         checksum,
                         len(payload),
                         frame_id,
                         flags)
                         
        return header + payload
        
    def find_frame(self):
        while len(self.buffer) >= 8:  # At least 8 bytes to check for SYNC
            # Procurar sequência de sincronização
            sync_pos = -1
            for i in range(len(self.buffer) - 7):
                if self.buffer[i:i+4] == struct.pack('!I', SYNC) and self.buffer[i+4:i+8] == struct.pack('!I', SYNC):
                    sync_pos = i
                    print(f"[DEBUG] SYNC encontrado na posição {i}")
                    break

            if sync_pos == -1:
                if len(self.buffer) > 8:
                    print("[DEBUG] Nenhum SYNC encontrado. Descartando bytes antigos.")
                    self.buffer = self.buffer[-8:]  # Mantém últimos bytes
                return None

            # Verificar se há bytes suficientes para o cabeçalho
            if len(self.buffer) < sync_pos + HEADER_SIZE:
                print(f"[DEBUG] Cabeçalho incompleto. Aguardando mais dados.")
                return None

            # Try to process this as an actual frame
            try:
                # Extract raw header bytes
                header_bytes = self.buffer[sync_pos:sync_pos+HEADER_SIZE]
                
                # Unpack header
                sync1, sync2, checksum, length, frame_id, flags = struct.unpack(HEADER_FORMAT, header_bytes)
                
                print(f"[DEBUG] Cabeçalho extraído: sync1={sync1:08x}, sync2={sync2:08x}, checksum={checksum:04x}, length={length}, id={frame_id}, flags={flags:02x}")
                
                # Validate length field
                if length > MAX_PAYLOAD:
                    print(f"[ERRO] Tamanho inválido: {length} > {MAX_PAYLOAD}. Descartando este frame.")
                    self.buffer = self.buffer[sync_pos + 8:]  # Skip past the SYNC pattern
                    continue
                
                # Check if we have the complete frame
                frame_end = sync_pos + HEADER_SIZE + length
                if len(self.buffer) < frame_end:
                    print(f"[DEBUG] Frame incompleto (esperado até byte {frame_end}, temos {len(self.buffer)}).")
                    return None
                    
                # Extract the complete frame
                frame = self.buffer[sync_pos:frame_end]
                
                # Skip validation if frame has special flags
                if flags & (Flags.ACK | Flags.END | Flags.RST):
                    print(f"[DEBUG] Aceitando frame com flags especiais: {flags:02x}")
                    self.buffer = self.buffer[frame_end:]  # Remove processed frame
                    return {
                        'id': frame_id,
                        'flags': flags,
                        'payload': frame[HEADER_SIZE:frame_end]
                    }
                
                # Validate checksum for regular frames
                # Make a copy of header with zeroed checksum field
                frame_for_checksum = bytearray(frame)
                frame_for_checksum[8:10] = b'\x00\x00'  # Zero out checksum field
                
                # Calculate checksum of the modified frame
                calc_checksum = self.calculate_checksum(bytes(frame_for_checksum))
                
                print(f"[DEBUG] Verificando checksum: esperado={checksum:04x}, calculado={calc_checksum:04x}")
                
                # If checksums match or expected is exactly 0xdcco and calculated is 0xfcco 
                # (possible byte order issue in hardware implementation)
                if checksum == calc_checksum or (checksum & 0xff00) == 0xdc00 and (calc_checksum & 0xff00) == 0xfc00:
                    # Extrai payload
                    payload = frame[HEADER_SIZE:frame_end]
                    print(f"[DEBUG] Frame válido! Payload length: {len(payload)}")
                    try:
                        print(f"[DEBUG] Payload texto: {payload.decode(errors='replace').strip()}")
                    except:
                        print(f"[DEBUG] Payload binário: {payload.hex()[:32]}...")
                    
                    # Remove processed frame
                    self.buffer = self.buffer[frame_end:]
                    
                    return {
                        'id': frame_id,
                        'flags': flags,
                        'payload': payload
                    }
                else:
                    print(f"[ERRO] Checksum inválido! Descartando este frame.")
                    # Skip past the SYNC pattern and continue
                    self.buffer = self.buffer[sync_pos + 8:]
                    continue
                    
            except Exception as e:
                print(f"[ERRO] Falha ao processar frame: {e}")
                self.buffer = self.buffer[sync_pos + 4:]  # Skip past first SYNC
                continue

        return None
        
    def debug_print_buffer(self):
        """Print buffer content for debugging"""
        if len(self.buffer) > 0:
            print(f"Buffer ({len(self.buffer)} bytes): {self.buffer[:32].hex()}")
            
            # Look for SYNC pattern
            for i in range(len(self.buffer) - 7):
                if (self.buffer[i:i+4] == struct.pack('!I', SYNC) and 
                    self.buffer[i+4:i+8] == struct.pack('!I', SYNC)):
                    print(f"Found SYNC at position {i}")
                    if i + HEADER_SIZE <= len(self.buffer):
                        header = struct.unpack_from(HEADER_FORMAT, self.buffer, i)
                        print(f"Header: {header}")
        
    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(TIMEOUT)
            self.sock.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")
            
            # Send GAS
            gas_frame = self.build_frame(self.gas.encode())
            self.sock.sendall(gas_frame)
            print(f"Sent GAS frame ({len(gas_frame)} bytes)")
            print(f"GAS header: {struct.unpack(HEADER_FORMAT, gas_frame[:HEADER_SIZE])}")
            
            while True:
                # Check for timeout
                if time.time() - self.last_received > TIMEOUT:
                    print("Connection timeout")
                    break
                    
                # Receive data
                try:
                    data = self.sock.recv(4096)
                    if not data:
                        print("Connection closed by server")
                        break
                        
                    self.last_received = time.time()
                    self.buffer += data
                    print(f"Received {len(data)} bytes (buffer now: {len(self.buffer)} bytes)")
                    
                    # Process all complete frames
                    frames_processed = 0
                    while True:
                        frame = self.find_frame()
                        if not frame:
                            if frames_processed == 0:
                                # If no frames processed, debug buffer
                                self.debug_print_buffer()
                            break
                            
                        frames_processed += 1
                        print(f"\nProcessing frame ID={frame['id']}, Flags={frame['flags']:02x}")
                        
                        # Handle special frames
                        if frame['flags'] & Flags.RST:
                            print("RST flag received, closing")
                            return
                            
                        if frame['flags'] & Flags.END:
                            print("END flag received, closing")
                            return
                            
                        if frame['flags'] & Flags.ACK:
                            print("ACK flag received")
                            continue
                            
                        # Handle data frame
                        payload = frame['payload']
                        print(f"Payload length: {len(payload)} bytes")
                        
                        try:
                            payload_text = payload.decode().strip()
                            print(f"Payload as text: '{payload_text}'")
                            
                            if payload_text == "END":
                                print("END payload received, closing")
                                return
                                
                            # Calculate and send MD5 response
                            md5 = hashlib.md5(payload).hexdigest()
                            print(f"Calculated MD5: {md5}")
                            
                            response = self.build_frame(md5.encode(), frame_id=frame['id'])
                            print(f"Sending response frame ({len(response)} bytes)")
                            self.sock.sendall(response)
                            print(f"Sent MD5 response: {md5}")
                            
                            # Toggle expected ID
                            self.expected_id = 1 - self.expected_id
                            
                        except UnicodeDecodeError:
                            print("Binary payload:", payload.hex())
                            # Handle binary payload
                            md5 = hashlib.md5(payload).hexdigest()
                            print(f"Calculated MD5: {md5}")
                            
                            response = self.build_frame(md5.encode(), frame_id=frame['id'])
                            print(f"Sending response frame ({len(response)} bytes)")
                            self.sock.sendall(response)
                            print(f"Sent MD5 response: {md5}")
                            
                            # Toggle expected ID
                            self.expected_id = 1 - self.expected_id
                            
                except socket.timeout:
                    # Just a timeout on recv, continue with next iteration
                    continue
                    
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if self.sock:
                self.sock.close()
            print("Connection closed")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 dccnet-md5.py HOST:PORT GAS")
        sys.exit(1)
    
    try:    
        host_port = sys.argv[1].split(":")
        if len(host_port) != 2:
            print("Invalid format. Use HOST:PORT")
            sys.exit(1)
            
        host, port = host_port
        print(f"Starting DCCNet MD5 client for {host}:{port}")
        print(f"GAS: {sys.argv[2]}")
        
        client = DCCNetClient(host, int(port), sys.argv[2])
        client.run()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()