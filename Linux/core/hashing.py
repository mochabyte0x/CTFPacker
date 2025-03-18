
class Hasher:

    def Hasher(input_string: str, INITIAL_SEED: int, INITIAL_HASH: int) -> int:

        hash_value = INITIAL_HASH & 0xFFFFFFFF
        
        for c in input_string.encode('ascii'):
            hash_value = ((hash_value << INITIAL_SEED) & 0xFFFFFFFF) + hash_value
            hash_value = (hash_value + c) & 0xFFFFFFFF
        
        return f"0x{hash_value:08X}"