# student.py
# Sensor Telemetry Decoder - Complete Implementation for 10 Tasks

class TelemetryDecoder:
    def __init__(self):
        pass

    # --- TASK 1: Unsigned Integer Conversion (Manual Bit Shifting) ---
    def decode_unsigned_int(self, byte_list, endianness='big'):
        """
        Converts a list/bytes of raw bytes into an unsigned integer using manual bit shifting.
        Does not use int.from_bytes or struct.
        """
        value = 0
        if endianness == 'little':
            for i, b in enumerate(byte_list):
                value |= (b & 0xFF) << (8 * i)
        else: # big endian
            for b in byte_list:
                value = (value << 8) | (b & 0xFF)
        return value

    # --- TASK 2: Signed Integers using Two's Complement ---
    def decode_signed_int(self, byte_list, endianness='big'):
        """
        Decodes signed integers using two's complement representation.
        """
        unsigned_val = self.decode_unsigned_int(byte_list, endianness)
        bit_length = len(byte_list) * 8
        
        # Check sign bit (most significant bit)
        if unsigned_val & (1 << (bit_length - 1)):
            unsigned_val -= (1 << bit_length)
            
        return unsigned_val

    # --- TASK 3: IEEE 754 Single-Precision Floating-Point Decoding ---
    def decode_ieee754_float(self, byte_list, endianness='big'):
        """
        Decodes a 4-byte IEEE 754 single-precision float manually.
        """
        raw_int = self.decode_unsigned_int(byte_list, endianness)
        
        if raw_int == 0:
            return 0.0
            
        sign = (raw_int >> 31) & 0x01
        exponent = (raw_int >> 23) & 0xFF
        fraction = raw_int & 0x7FFFFF
        
        if exponent == 255:
            if fraction == 0:
                return float('-inf') if sign else float('inf')
            return float('nan')
            
        if exponent == 0:
            # Denormalized number
            float_val = (fraction / (2**23)) * (2 ** -126)
        else:
            # Normalized number
            float_val = (1.0 + (fraction / (2**23))) * (2 ** (exponent - 127))
            
        return -float_val if sign else float_val

    # --- TASK 4: Endianness Determination ---
    def determine_endianness(self, sample_bytes, plausible_min, plausible_max):
        """
        Determines whether big-endian or little-endian produces a value within plausible ranges.
        """
        val_big = self.decode_unsigned_int(sample_bytes, 'big')
        val_little = self.decode_unsigned_int(sample_bytes, 'little')
        
        if plausible_min <= val_big <= plausible_max:
            return 'big'
        elif plausible_min <= val_little <= plausible_max:
            return 'little'
        return 'unknown'

    # --- TASK 5: Structured Packet Parsing with Padding ---
    def parse_packet(self, packet_bytes):
        """
        Parses a structured packet containing header, sensor ID, padding, and values.
        """
        if len(packet_bytes) < 4:
            raise ValueError("Packet too short")
            
        sensor_id = packet_bytes[0]
        # packet_bytes[1] is padding
        val_bytes = packet_bytes[2:4]
        sensor_value = self.decode_unsigned_int(val_bytes, 'big')
        
        return {
            "sensor_id": sensor_id,
            "value": sensor_value
        }

    # --- TASK 6: Checksum Validation ---
    def validate_checksum(self, packet_bytes):
        """
        Validates packet integrity using an XOR checksum.
        """
        if not packet_bytes:
            return False
            
        payload = packet_bytes[:-1]
        expected_checksum = packet_bytes[-1]
        
        calculated = 0
        for b in payload:
            calculated ^= b
            
        return calculated == expected_checksum

    # --- TASK 7: Robust Stream Processing ---
    def process_stream(self, stream_of_packets):
        """
        Processes a stream of packets, ignoring corrupted or malformed ones without crashing.
        """
        results = []
        for pkt in stream_of_packets:
            try:
                if not self.validate_checksum(pkt):
                    continue
                parsed = self.parse_packet(pkt)
                results.append(parsed)
            except Exception:
                continue
        return results

    # --- TASK 8: Virtual-to-Physical Address Translation ---
    def translate_address(self, virtual_address, page_table, page_size=4096):
        """
        Translates a virtual memory address into a physical address using a page table.
        """
        page_number = virtual_address // page_size
        offset = virtual_address % page_size
        
        if page_number not in page_table:
            raise MemoryError("Page fault: Virtual address not mapped")
            
        frame_number = page_table[page_number]
        return (frame_number * page_size) + offset

    # --- TASK 9: First-Fit Dynamic Memory Allocator ---
    def first_fit_allocate(self, memory_blocks, requested_size):
        """
        Simulates a first-fit heap allocator.
        """
        for block in memory_blocks:
            if block.get('free', False) and block.get('size', 0) >= requested_size:
                block['free'] = False
                return block.get('id')
        return None

    # --- TASK 10: Encoding and Decoding Verification ---
    def verify_roundtrip(self, original_value):
        """
        Verifies that encoding a number and decoding it back preserves the original value.
        """
        high_byte = (original_value >> 8) & 0xFF
        low_byte = original_value & 0xFF
        encoded = [high_byte, low_byte]
        
        decoded = self.decode_unsigned_int(encoded, 'big')
        return decoded == original_value
