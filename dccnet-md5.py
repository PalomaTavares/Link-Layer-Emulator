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
        self.current_id = 0             # ID for outgoing data frames
        self.last_received_id = None    # Last received frame ID
        self.last_received_checksum = None  # Checksum of last received frame
        self.last_frame = None          # Last sent frame (for retransmission)
        self.send_queue = []            # Queue of frames to send
        self.last_sent_time = 0         # Time when last frame was sent
        self.retries = 0                # Retransmission counter
        self.active = True              # Connection status
        self.sending_lock = threading.Lock()  # Lock for sending operations
        self.processing_lock = threading.Lock()  # Lock for frame processing
        self.end_received = False       # Track if END flag was received
        self.waiting_for_ack = False    # Track if waiting for an ACK
        self.shutdown_in_progress = False  # Flag to indicate graceful shutdown is in progress

    def checksum(self, data):
        """Calculate Internet checksum"""
        if len(data) % 2 == 1:
            data += b'\x00'
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) | data[i+1]
            total = (total & 0xffff) + (total >> 16)
        return ~total & 0xffff

    def build_frame(self, payload=b'', flags=0, frame_id=None):
        """Build a DCCNET frame"""
        if frame_id is None:
            frame_id = self.current_id

        payload = payload[:MAX_PAYLOAD]

        # Create header with zero checksum first
        header = struct.pack(HEADER_FORMAT,
                           SYNC, SYNC, 0, len(payload), frame_id, flags)

        # Calculate checksum over the entire frame
        checksum = self.checksum(header + payload)

        # Rebuild header with calculated checksum
        header = struct.pack(HEADER_FORMAT,
                         SYNC, SYNC, checksum, len(payload), frame_id, flags)

        return header + payload

    def send_frame(self, payload=b'', flags=0, frame_id=None):
        """Send a frame and store for retransmission if needed"""
        try:
            with self.sending_lock:
                # Use current_id if frame_id not specified
                if frame_id is None:
                    frame_id = self.current_id

                # Build the frame
                frame = self.build_frame(payload, flags, frame_id)

                try:
                    # If this is an ACK or RST or END, send it immediately without retransmission
                    if (flags & ACK_FLAG) or (flags & RST_FLAG) or (flags & END_FLAG):
                        self.sock.sendall(frame)
                        sync1, sync2, checksum, length, f_id, f_flags = struct.unpack_from(
                            HEADER_FORMAT, frame, 0)
                        print(f"Sent frame (ID={f_id}, Length={length}, Flags={f_flags:02x})")
                    else:
                        # For data frames: if already waiting for an ACK, queue this frame
                        if self.waiting_for_ack:
                            print(f"Queuing frame (ID={frame_id}) - waiting for ACK")
                            self.send_queue.append((payload, flags, frame_id))
                        else:
                            # Send the frame and start waiting for ACK
                            self.sock.sendall(frame)
                            sync1, sync2, checksum, length, f_id, f_flags = struct.unpack_from(
                                HEADER_FORMAT, frame, 0)
                            print(f"Sent frame (ID={f_id}, Length={length}, Flags={f_flags:02x})")

                            # Store for retransmission and mark as waiting for ACK
                            self.last_frame = frame
                            self.last_sent_time = time.time()
                            self.retries = 0
                            self.waiting_for_ack = True

                except Exception as e:
                    print(f"Send error: {e}")
                    self.active = False
        except Exception as e:
            print(f"Send frame exception: {e}")

    def validate_frame(self, frame):
        """Validate a received frame"""
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

            # Verify checksum
            frame_copy = bytearray(frame)
            frame_copy[8:10] = b'\x00\x00'  # Zero out checksum field
            if self.checksum(frame_copy) != checksum:
                print("Checksum mismatch")
                return False

            return True

        except Exception as e:
            print(f"Validation error: {e}")
            return False

    def process_frame(self, frame):
        """Process a received frame"""
        try:
            with self.processing_lock:
                if not self.validate_frame(frame):
                    return

                sync1, sync2, checksum, length, frame_id, flags = struct.unpack_from(
                    HEADER_FORMAT, frame, 0)
                payload = frame[HEADER_SIZE:HEADER_SIZE + length]

                print(f"Received valid frame - ID: {frame_id}, Flags: {flags:02x}, Length: {length}")

                # Handle RST frame (Immediate termination)
                if flags & RST_FLAG:
                    print("RST received - closing connection")
                    if payload:
                        try:
                            print(f"RST reason: {payload.decode().strip()}")
                        except UnicodeDecodeError:
                            print(f"RST with binary payload ({len(payload)} bytes)")
                    self.active = False
                    return # Stop processing immediately

                # Handle ACK frame
                if flags & ACK_FLAG:
                    with self.sending_lock:
                        print(f"Received ACK with ID={frame_id}, expecting ID={self.current_id}, waiting={self.waiting_for_ack}")
                        ack_processed = False
                        if self.waiting_for_ack and frame_id == self.current_id:
                            print(f"Valid ACK received for ID={frame_id}")
                            ack_processed = True
                            # Toggle ID for next outgoing data frame
                            self.current_id = 1 - self.current_id
                            self.last_frame = None  # Clear stored frame for retransmission
                            self.waiting_for_ack = False  # No longer waiting for THIS ACK
                            self.retries = 0 # Reset retries for the acknowledged frame

                            # --- Start of Termination Logic within ACK processing ---

                            # Check 1: Was this the ACK for our own client-initiated END?
                            if self.shutdown_in_progress:
                                print("ACK received for client-initiated END frame. Closing.")
                                self.active = False
                                return # Exit processing

                            # Check 2: Was END already received from the server, and are we done sending?
                            # This handles the race condition where END arrived before this ACK.
                            if self.end_received and not self.send_queue:
                                print("END flag was previously received from server, and final ACK received. Closing.")
                                self.active = False
                                return # Exit processing

                            # --- End of Termination Logic within ACK processing ---

                            # If there are queued frames, send the next one
                            if self.send_queue:
                                next_payload, next_flags, next_id = self.send_queue.pop(0)
                                # Use the *new* current_id for the queued frame
                                print(f"Sending queued frame (ID={self.current_id}, Flags={next_flags:02x})")
                                # Call internal send logic to avoid re-locking
                                self._send_frame_internal(next_payload, next_flags, self.current_id)
                            # else: # If nothing queued AND we received the server's END previously
                                # This check is now redundant due to Check 2 above.
                                # pass

                        else: # Unexpected ACK
                            print(f"Unexpected or duplicate ACK received (ID={frame_id}, expecting={self.current_id}, waiting={self.waiting_for_ack})")
                            # Do not change state for unexpected ACKs

                    # Return after processing ACK (whether expected or not)
                    # We don't process payload or send another ACK for an ACK frame
                    return


                # --- Handle Data Frame (potentially with END flag) ---

                # Process END flag if present *on a data frame*
                is_end_frame = bool(flags & END_FLAG)
                if is_end_frame:
                    print("END flag received from server on data frame")
                    self.end_received = True
                    # Note: We don't close immediately here, must ACK first and ensure we aren't waiting for other ACKs.

                # Process Data Payload
                frame_checksum = checksum
                is_duplicate = (self.last_received_id == frame_id and
                                self.last_received_checksum == frame_checksum)

                # Accept frame if: New ID or Duplicate of last received
                if frame_id != self.last_received_id or is_duplicate:
                    # Store frame info to detect duplicates
                    self.last_received_id = frame_id
                    self.last_received_checksum = frame_checksum

                    # Process payload only if it's a *new* frame (not a duplicate retransmission)
                    if not is_duplicate and payload:
                        try:
                            text = payload.decode('utf-8')
                            print(f"Received text: {text.strip()}")
                            for line in text.splitlines():
                                if line:
                                    md5_input = line.encode('utf-8')
                                    md5_hex = hashlib.md5(md5_input).hexdigest() + "\n"
                                    print(f"MD5 input: '{line}'")
                                    print(f"MD5 response: {md5_hex.strip()}")
                                    # Send MD5 response as data frame. This might queue if waiting for ACK.
                                    # Use self.send_frame which handles locking and queuing
                                    self.send_frame(md5_hex.encode('utf-8'))
                        except UnicodeDecodeError:
                            print(f"Binary data received ({len(payload)} bytes), sending ACK.")
                        except Exception as e:
                            print(f"Error processing payload: {e}")
                    elif is_duplicate:
                        print("Duplicate data frame detected, re-sending ACK.")
                    #else: # No payload, potentially just an END frame or keepalive
                    #    print("Data frame without payload received.")


                    # Always send ACK for valid data frames (new or duplicate)
                    # Send ACK using the received frame's ID
                    print(f"Sending ACK for data frame ID={frame_id}")
                    self.send_frame(b'', ACK_FLAG, frame_id)

                    # Final check: If this frame had the END flag, AND we are not waiting for any ACK,
                    # AND the send queue is empty, we can close now.
                    if is_end_frame and not self.waiting_for_ack and not self.send_queue:
                         print("Processed frame with END flag, ACK sent, nothing pending. Closing.")
                         self.active = False
                         return # Exit processing

                else: # Unexpected data frame ID
                     print(f"Unexpected data frame ID received: {frame_id}, expected: {1 - self.last_received_id if self.last_received_id is not None else 0}. Discarding.")
                     # Do not ACK unexpected IDs

        except Exception as e:
            print(f"Process frame exception: {e}")
            # Consider sending RST on critical processing errors
            # self.send_rst_frame("Internal processing error")
            self.active = False # Force close on unhandled exception during processing

    def _send_frame_internal(self, payload=b'', flags=0, frame_id=None):
        """Internal send method assuming lock is already held"""
        if frame_id is None:
            frame_id = self.current_id

        frame = self.build_frame(payload, flags, frame_id)

        try:
            self.sock.sendall(frame)
            sync1, sync2, checksum, length, f_id, f_flags = struct.unpack_from(
                HEADER_FORMAT, frame, 0)
            print(f"Sent frame (Internal - ID={f_id}, Length={length}, Flags={f_flags:02x})")

            # If it's a data frame (not ACK/RST), store for retransmission and set waiting flag
            if not (flags & ACK_FLAG) and not (flags & RST_FLAG):
                self.last_frame = frame
                self.last_sent_time = time.time()
                self.retries = 0
                self.waiting_for_ack = True

        except Exception as e:
            print(f"Internal send error: {e}")
            self.active = False

    def retransmit_check(self):
        """Background thread for retransmission handling"""
        while self.active:
            try:
                with self.sending_lock:
                    if self.waiting_for_ack and self.last_frame and time.time() - self.last_sent_time > TIMEOUT:
                        if self.retries < MAX_RETRIES:
                            try:
                                # Retransmit exactly the same frame
                                self.sock.sendall(self.last_frame)
                                self.retries += 1
                                self.last_sent_time = time.time()

                                # Debug: Print frame details
                                sync1, sync2, checksum, length, frame_id, flags = struct.unpack_from(
                                    HEADER_FORMAT, self.last_frame, 0)
                                print(f"Retransmitting frame (ID={frame_id}, Length={length}, "
                                      f"Flags={flags:02x}, Attempt={self.retries}/{MAX_RETRIES})")
                            except Exception as e:
                                print(f"Retransmit error: {e}")
                                self.active = False
                        else:
                            print("Max retries reached - sending RST")
                            # Don't use self.send_frame here to avoid locking issues
                            rst_frame = self.build_frame(b'Max retries exceeded', RST_FLAG, 0xFFFF)
                            try:
                                self.sock.sendall(rst_frame)
                            except Exception:
                                pass
                            self.active = False
            except Exception as e:
                print(f"Retransmission thread error: {e}")

            time.sleep(0.1)

    def receive_loop(self):
        """Main receive loop"""
        while self.active:
            try:
                data = self.sock.recv(4096)
                if not data:
                    print("Connection closed by server")
                    self.active = False
                    break

                self.buffer += data
                print(f"Received {len(data)} bytes, buffer now {len(self.buffer)} bytes")

                # Process complete frames
                while self.active and len(self.buffer) >= HEADER_SIZE:
                    # Find SYNC pattern (two consecutive SYNC values)
                    sync_pos = -1
                    for i in range(len(self.buffer) - 7):
                        if (struct.unpack_from('!I', self.buffer, i)[0] == SYNC and
                            struct.unpack_from('!I', self.buffer, i+4)[0] == SYNC):
                            sync_pos = i
                            break

                    if sync_pos == -1:
                        # No SYNC pattern found, keep last few bytes for next attempt
                        if len(self.buffer) > 8:
                            self.buffer = self.buffer[-8:]
                        break

                    # Discard any data before SYNC
                    if sync_pos > 0:
                        print(f"Discarding {sync_pos} bytes before SYNC")
                        self.buffer = self.buffer[sync_pos:]
                        sync_pos = 0

                    # Check if we have enough data to extract the length
                    if len(self.buffer) < HEADER_SIZE:
                        break

                    # Get frame length from header
                    length = struct.unpack_from('!H', self.buffer, 10)[0]
                    frame_end = HEADER_SIZE + length

                    # Check if we have the complete frame
                    if len(self.buffer) < frame_end:
                        break

                    # Extract the frame and remove it from buffer
                    frame = self.buffer[:frame_end]
                    self.buffer = self.buffer[frame_end:]

                    # Process the frame
                    self.process_frame(frame)

            except socket.timeout:
                # This is expected with our timeout setting
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
                    if self.waiting_for_ack:
                        print("Still waiting for ACK, queueing END frame")
                        self.send_queue.append((b'', END_FLAG, self.current_id))
                    else:
                        end_frame = self.build_frame(b'', END_FLAG)
                        self.sock.sendall(end_frame)
                        sync1, sync2, checksum, length, f_id, f_flags = struct.unpack_from(
                            HEADER_FORMAT, end_frame, 0)
                        print(f"Sent END frame (ID={f_id}, Length={length}, Flags={f_flags:02x})")

                        # Store for retransmission
                        self.last_frame = end_frame
                        self.last_sent_time = time.time()
                        self.retries = 0
                        self.waiting_for_ack = True

                        # Adicionar um timer para esperar pelo ACK do END
                        threading.Timer(5, self._force_close_after_end).start()

                finally:
                    self.sending_lock.release()
            else:
                print("Could not acquire lock for END frame, sending RST instead")
                self.send_rst_frame("Client shutdown - lock timeout")
        except Exception as e:
            print(f"Error sending END frame: {e}")
            self.send_rst_frame("Client shutdown - error")

    def send_rst_frame(self, reason="Client shutdown"):
        """Send RST frame for immediate termination"""
        try:
            rst_frame = self.build_frame(reason.encode(), RST_FLAG, 0xFFFF)
            self.sock.sendall(rst_frame)
            print(f"Sent RST frame: {reason}")
        except Exception as e:
            print(f"Error sending RST frame: {e}")
        finally:
            self.active = False

    def signal_handler(self, sig, frame):
        """Handle interrupt signals"""
        print("\nUser interrupt - initiating graceful shutdown")
        
        # Attempt to send END frame to close connection gracefully
        if self.active and not self.shutdown_in_progress:
            self.send_end_frame()
            
            # Give some time for the END frame and its ACK to be processed
            # but don't block indefinitely
            timeout = time.time() + 5  # 5 second timeout
            while self.active and time.time() < timeout:
                time.sleep(0.2)
                
            # If still active after timeout, force close with RST
            if self.active:
                print("Graceful shutdown timed out, sending RST")
                self.send_rst_frame("Client shutdown - timeout")
                
        # This will exit if we're caught in a blocking I/O operation
        sys.exit(0)

    def run(self):
        """Main client method"""
        try:
            # Set up signal handler for graceful termination
            signal.signal(signal.SIGINT, self.signal_handler)
            
            # Connect to server
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(0.5)
            self.sock.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")

            # Start retransmission thread
            retrans_thread = threading.Thread(target=self.retransmit_check, daemon=True)
            retrans_thread.start()

            # Send GAS with ID 0
            self.send_frame(self.gas.encode())

            # Start receive loop
            self.receive_loop()

        except KeyboardInterrupt:
            # This should be caught by the signal handler
            pass
        except Exception as e:
            print(f"Error: {e}")
        finally:
            # Ensure graceful shutdown
            if self.active:
                self.active = False

            if self.sock:
                try:
                    # Send a final RST frame if connection wasn't closed gracefully
                    if not self.end_received and not self.shutdown_in_progress:
                        self.send_rst_frame("Client shutdown - cleanup")
                except Exception:
                    pass

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