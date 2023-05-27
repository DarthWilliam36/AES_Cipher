import numpy as np
import base64

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)


class AES:
    def __init__(self, key):
        self.key_schedule = self.key_expansion(key)

    @staticmethod
    def array_to_str(arr):
        x, y = arr.shape
        string = ''
        for i in range(x):
            for j in range(y):
                if arr[i, j] != 0:
                    string += chr(arr[i, j])
        return string

    @staticmethod
    def array_to_hex(arr):
        hex_arr = np.vectorize(lambda x: hex(x)[2:].zfill(2))(arr)
        return hex_arr

    @staticmethod
    def arr_to_list(arr):
        x, y = arr.shape
        lst = []
        for i in range(x):
            for j in range(y):
                lst.append(arr[i, j])
        return lst

    @staticmethod
    def encode_str(string):
        string = bytes(string, 'utf-8')
        return base64.b64encode(string).decode()

    @staticmethod
    def encode_list(lst):
        binary_data = b''
        for i in lst:
            binary_data += int(i).to_bytes(1, "big")
        encoded_data = base64.b64encode(binary_data).decode()
        return encoded_data

    @staticmethod
    def decode_to_list(string_data):
        decoded_data = base64.b64decode(string_data)
        integer_list = []
        for i in decoded_data:
            integer_list.append(i)
        return integer_list

    @staticmethod
    def state_array_padding(arr):
        for i in range(4 - len(arr[-1])):
            arr[-1].append(0)
        if len(arr) % 4:
            for i in range(4 - len(arr) % 4):
                arr.append([0 for i in range(4)])
        return arr

    @staticmethod
    def gf_multiply(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            carry = a & 0x80
            a <<= 1
            if carry:
                a ^= 0x1B  # Irreducible polynomial x^8 + x^4 + x^3 + x + 1
            b >>= 1
        return p

    @staticmethod
    def sub_bytes(block):
        x, y = block.shape
        new_block = block.copy()
        for i in range(x):
            for j in range(y):
                replace = block[i, j]
                row = (replace & 0xF0) >> 4
                col = replace & 0x0F
                new_block[i, j] = s_box[row * 16 + col]
        return new_block

    @staticmethod
    def inv_sub_bytes(block):
        x, y = block.shape
        new_block = block.copy()
        for i in range(x):
            for j in range(y):
                replace = block[i, j]
                row = (replace & 0xF0) >> 4
                col = replace & 0x0F
                new_block[i, j] = inv_s_box[row * 16 + col]
        return new_block

    @staticmethod
    def shift_rows(block):
        shifted_matrix = block.copy()
        for i in range(4):
            new_row = []
            for j in range(4):
                new_row.append(shifted_matrix[(j + i) % 4, i])
            for j in range(4):
                shifted_matrix[j, i] = new_row[j]
        return shifted_matrix

    @staticmethod
    def inv_shift_rows(block):
        unshifted_matrix = block.copy()
        for i in range(4):
            new_row = []
            for j in range(4):
                new_row.append(unshifted_matrix[(j - i) % 4, i])
            for j in range(4):
                unshifted_matrix[j, i] = new_row[j]
        return unshifted_matrix

    def mix_col(self, block):
        mix_matrix = np.array([[2, 3, 1, 1],
                               [1, 2, 3, 1],
                               [1, 1, 2, 3],
                               [3, 1, 1, 2]])
        mixed_matrix = np.zeros_like(block)
        for row in range(4):
            for col in range(4):
                prev = 0
                for i in range(4):
                    prev ^= self.gf_multiply(mix_matrix[row, i], block[col, i])
                mixed_matrix[col, row] = prev % 256
        return mixed_matrix

    def inv_mix_col(self, block):
        mix_matrix = np.array([[14, 11, 13, 9],
                               [9, 14, 11, 13],
                               [13, 9, 14, 11],
                               [11, 13, 9, 14]])
        unmixed_matrix = np.copy(block)
        for row in range(4):
            for col in range(4):
                prev = 0
                for i in range(4):
                    prev ^= self.gf_multiply(mix_matrix[row, i], block[col, i])
                unmixed_matrix[col, row] = prev % 256
        return unmixed_matrix

    @staticmethod
    def key_expansion(key):
        rcon_table = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
        num_rounds = {16: 10, 24: 12, 32: 14}
        num_key_words = len(key) // 4
        if not len(key) == 16:
            raise RuntimeError("Incorrect key length")
        key_schedule = [key[i:i + 4] for i in range(0, len(key), 4)]
        for i in range(len(key_schedule)):
            word = []
            for j in range(len(key_schedule[i])):
                if key_schedule[i][j].isdigit():
                    word.append(int(key_schedule[i][j]))
                else:
                    word.append(ord(key_schedule[i][j]))
            key_schedule[i] = word
        for i in range(num_key_words, 4 * (10 + 1)):
            temp = key_schedule[i - 1]
            if i % num_key_words == 0:
                temp = [temp[1], temp[2], temp[3], temp[0]]
                temp = [s_box[b] for b in temp]
                temp[0] ^= rcon_table[(i // num_key_words) - 1]
            new_word = [key_schedule[i - num_key_words][j] ^ temp[j] for j in range(4)]
            key_schedule.append(new_word)
        return np.array(key_schedule)

    @staticmethod
    def add_round_key(block, key_block):
        new_block = np.bitwise_xor(block, key_block)
        return new_block

    def encrypt(self, plain_text):
        state_array = []
        for i in range(0, len(plain_text), 4):
            word = [ord(i) for i in plain_text[i:i + 4]]
            state_array.append(word)
        state_array = self.state_array_padding(state_array)
        state_array = np.array(state_array)
        cipher_text = state_array.copy()
        for i in range(0, len(state_array), 4):
            block = np.array(state_array[i:i + 4])
            block = self.add_round_key(block, self.key_schedule[:4])
            for j in range(9):
                block = self.sub_bytes(block)
                block = self.shift_rows(block)
                block = self.mix_col(block)
                block = self.add_round_key(block, self.key_schedule[j * 4 + 4:j * 4 + 8])
            block = self.sub_bytes(block)
            block = self.shift_rows(block)
            block = self.add_round_key(block, self.key_schedule[-4:])
            cipher_text[i:i + 4] = block
        cipher_list = self.arr_to_list(cipher_text)
        cipher_text_str = self.encode_list(cipher_list)
        return cipher_text_str

    def decrypt(self, cipher_text):
        cipher_text = self.decode_to_list(cipher_text)
        plain_text = []
        for i in range(0, len(cipher_text), 4):
            word = [i for i in cipher_text[i:i + 4]]
            plain_text.append(word)
        plain_text = self.state_array_padding(plain_text)
        plain_text = np.array(plain_text)
        for i in range(0, len(plain_text), 4):
            block = np.array(plain_text[i:i + 4])
            block = self.add_round_key(block, self.key_schedule[-4:])
            block = self.inv_shift_rows(block)
            block = self.inv_sub_bytes(block)
            for j in range(9):
                block = self.add_round_key(block, self.key_schedule[j * -4 - 8:j * -4 - 4])
                block = self.inv_mix_col(block)
                block = self.inv_shift_rows(block)
                block = self.inv_sub_bytes(block)
            block = self.add_round_key(block, self.key_schedule[:4])
            plain_text[i:i + 4] = block
        plain_text_str = self.array_to_str(plain_text)
        return plain_text_str
