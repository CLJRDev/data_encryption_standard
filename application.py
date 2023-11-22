from tkinter import filedialog
import customtkinter 

# Chuyển đổi hệ hexa sang binary
def hex2bin(s):
	mp = {'0': '0000',
        '1': '0001',
        '2': '0010',
        '3': '0011',
        '4': '0100',
        '5': '0101',
        '6': '0110',
        '7': '0111',
        '8': '1000',
        '9': '1001',
        'a': '1010',
        'b': '1011',
        'c': '1100',
        'd': '1101',
        'e': '1110',
        'f': '1111'}
	bin = ''
	for i in range(len(s)):
		bin = bin + mp[s[i]]
	return bin

# Chuyển đổi hệ binary sang hexa
def bin2hex(s):
	mp = {'0000': '0',
        '0001': '1',
        '0010': '2',
        '0011': '3',
        '0100': '4',
        '0101': '5',
        '0110': '6',
        '0111': '7',
        '1000': '8',
        '1001': '9',
        '1010': 'a',
        '1011': 'b',
        '1100': 'c',
        '1101': 'd',
        '1110': 'e',
        '1111': 'f'}
	hex = ''
	for i in range(0, len(s), 4):
		ch = ''
		ch += s[i]
		ch += s[i + 1]
		ch += s[i + 2]
		ch += s[i + 3]
		hex += mp[ch]
	return hex

# Chuyển chuỗi sang nhị phân
def str2bin(str):
  res = ''.join(format(ord(i), '08b') for i in str)
  return res

# Chuyển đổi binary sang decimal
def bin2dec(binary):
	decimal, i = 0, 0
	while(binary != 0):
		dec = binary % 10
		decimal += dec * pow(2, i)
		binary = binary//10
		i += 1
	return decimal

# Chuyển đổi decimal sang binary
def dec2bin(num):
	res = bin(num).replace('0b', '')
  #Bù thêm bit 0 ở đầu cho các số ko đủ 4 bits
	if(len(res) % 4 != 0):
		count = 4  - len(res)
		for i in range(0, count):
			res = '0' + res
	return res

# Hoán vị
def permute(k, arr, n):
	permutation = ''
	for i in range(0, n):
		permutation += k[arr[i] - 1] #trừ đi 1 vì k chạy từ 0
	return permutation

#Dịch n bits sang trái
def shift_left(k, n):
	s = ''
	for i in range(n):
		for j in range(1, len(k)):
			s += k[j]
		s += k[0]
		k = s
		s = ''
	return k

# Hàm XOR bit
def xor(a, b):
	xor_x = ''
	for i in range(len(a)):
		if a[i] == b[i]:
			xor_x += '0'
		else:
			xor_x += '1'
	return xor_x

# Bảng hoán vị PC1
PC1 = [57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4]

# Bảng hoán vị PC2
PC2 = [14, 17, 11, 24, 1, 5,
      3, 28, 15, 6, 21, 10,
      23, 19, 12, 4, 26, 8,
      16, 7, 27, 20, 13, 2,
      41, 52, 31, 37, 47, 55,
      30, 40, 51, 45, 33, 48,
      44, 49, 39, 56, 34, 53,
      46, 42, 50, 36, 29, 32]

# Bảng hoán vị IP
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Bảng hoán vị E
E = [32, 1, 2, 3, 4, 5, 4, 5,
    6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32, 1]

# Bảng hoán vị P
P = [16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25]

# Bảng Si (1 <= i <= 8)
sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

		[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
		[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

		[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

		[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

		[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

		[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

		[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

		[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Bảng hoán vị nghịch đảo FP
FP = [40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25]

def create_key(key):
  # Key generation
  # --hex to binary
  key_hex_str = key.encode('utf-8').hex()
  key = hex2bin(key_hex_str)

  # Lấy khóa K 56 bits mới từ khóa cũ 64 bits
  key = permute(key, PC1, 56)

  # Số lượng bit phải dịch ở từng vòng lặp
  shift_table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

  # Tách khóa thành 2 phần (28 bits per part)
  left = key[0:28] 
  right = key[28:56] 

  key_box = [] # Mảng 16 khóa con binary
  for i in range(0, 16):
    #Dịch bits theo bảng dịch bits (shift_table)
    left = shift_left(left, shift_table[i])
    right = shift_left(right, shift_table[i])

    # Ghép 2 phần
    combine_str = left + right

    # Lấy ra ki sử dụng hoán vị PC2
    round_key = permute(combine_str, PC2, 48)
    key_box.append(round_key) #ki kiểu binary
  return key_box

def split_block(hex_str, action):
  blocks = []
  n = len(hex_str)//16
  start = 0
  end = 16
  for i in range(0,n):
    blocks.append(hex_str[start:end])
    start = end
    end += 16
  
  if action == False:
    return blocks
   
  if len(hex_str) % 16 != 0:
    lastPart = hex_str[len(hex_str)-len(hex_str)%16:len(hex_str)]
    count = len(hex_str)%16
    while count < 16:
      lastPart += '0'
      count += 1
    blocks.append(lastPart)
  return blocks

def encrypt(pt, key_box):
	pt = hex2bin(pt)

	# Hoán vị plain_text với bảng hoán vị IP
	pt = permute(pt, IP, 64)

	# Tách thành 2 phần L0 và R0
	left = pt[0:32] #32 bits đầu
	right = pt[32:64] #32 bits cuối
 
  #Lặp 16 lần
	for i in range(0, 16):
    # Mở rộng Ri từ 32 bits thành 48 bits bằng phép hoán vị E (Để công với khóa Ki 48 bits)
		right_expanded = permute(right, E, 48)

    # XOR Ki và Ri mở rộng
		B = xor(right_expanded, key_box[i])

    # Tính C từ vị trí row col trong bảng S
		C = ''
		for j in range(0, 8):
      # row = b0b5
			row = bin2dec(int(B[j * 6] + B[j * 6 + 5]))
      # col = b1b2b3b4
			col = bin2dec(int(B[j * 6 + 1] + B[j * 6 + 2] + B[j * 6 + 3] + B[j * 6 + 4]))
			cj = sbox[j][row][col]
			C += dec2bin(cj)

		# Hoán vị C với bảng hoán vị P để rút gọn C còn 32 bits => Ri
		R = permute(C, P, 32)

		# XOR left và R 
		result = xor(left, R)
		left = result

		# Hoán đổi left và right
		if(i != 15):
			left, right = right, left

	# Kết hợp left và right
	combine = left + right

	# Hoán vị FP (nghịch đảo của IP) để đưa ra được bản mã cuối cùng
	cipher_text = permute(combine, FP, 64)
	return cipher_text

def choose_file():
  filetypes = (('Text Document', '*.txt'), ('All files', '*.*'))
  file_name = filedialog.askopenfile(title='Open a file', initialdir='/', filetypes=filetypes)
  file_button.configure(text=file_name.name)

def save_file():
  file_text = str(output_text.get('0.0','end').strip())
  if(file_text == ''):
    return
  files = [('Text Document', '*.txt'), ('All Files', '*.*')] 
  file = filedialog.asksaveasfile(initialdir='E:/2023-2024', filetypes = files, defaultextension = files)
  if file is None:
    return 
  file.write(file_text)
  file.close()

def check_format(pt, key):
  input_notifi.configure(text='')
  key_notifi.configure(text='')
  result = True
  if(pt == ''):
    input_notifi.configure(text='Input cannot be empty!')
    result = False
  if (key == ''):
    key_notifi.configure(text='Key cannot be empty!')
    result = False
  elif (len(key) != 8):
    key_notifi.configure(text='Key must be 8 characters!')
    result = False
  return result

def check_is_file():
  if(file_button.cget('text').strip() != 'Choose file'):
    return True
  return False

def encrypt_button_clicked():
  if check_is_file() == True:
    file_name = file_button.cget('text')
    file = open(file_name,'r')
    with open(file_name) as f:
      pt = f.read()
    file.close()
    key = key_text.get('0.0','end').strip()
    if check_format(pt, key) == False:
      return
  else:
    pt = input_text.get('0.0','end').strip()
    key = key_text.get('0.0','end').strip()
    if check_format(pt, key) == False:
      return
  file_button.configure(text='Choose file')
  input_notifi.configure(text='')
  key_notifi.configure(text='')
  
  key_box = create_key(key)

  # -----------Quá trình mã hóa-----------
  hex_str = pt.encode('utf-8').hex()
  print('Original String:', pt)
  
  #Chia chuỗi đầu vào thành các block 64 bits
  blocks = split_block(hex_str, True)

  #Mã hóa từng block
  cipher_blocks = []
  for i in range(len(blocks)):  
    cipher_blocks.append(bin2hex(encrypt(blocks[i], key_box)))

  #Ghép các block lại và hiển thị
  cipher_text = ''
  for i in range(len(cipher_blocks)):
    cipher_text += cipher_blocks[i]
  output_text.delete('0.0','end')
  output_text.insert('0.0', cipher_text)
  print('Cipher text = ', cipher_text)
   
def decrypt_button_clicked():
  # #-----------Quá trình giải mã-----------
  if check_is_file() == True:
    file_name = file_button.cget('text')
    file = open(file_name,'r')
    with open(file_name) as f:
      hex_str = f.read()
    file.close()
    key = key_text.get('0.0','end').strip()
    if check_format(hex_str, key) == False:
      return
  else:
    hex_str = input_text.get('0.0','end').strip()
    key = key_text.get('0.0','end').strip()
    if check_format(hex_str, key) == False:
      return
  
  file_button.configure(text='Choose file')
  input_notifi.configure(text='')
  key_notifi.configure(text='')
  
  print('Original String:', hex_str)
  
  #Key giải mã bằng đảo ngược của key mã hóa
  key_box = create_key(key)[::-1]

  #Chia chuỗi đầu vào thành các block 64 bits
  blocks = split_block(hex_str, False)
  decipher_blocks = []

  for i in range(len(blocks)):
    decipher_blocks.append(bin2hex(encrypt(blocks[i], key_box)))

  decipher_string = ''
  for i in range(len(decipher_blocks)):
    decipher_string += decipher_blocks[i]
  hex_bytes = bytes.fromhex(decipher_string)
  deciphered_text = hex_bytes.decode('utf-8')
  output_text.delete('0.0','end')
  output_text.insert('0.0',deciphered_text)
  print('Deciphered text = ', deciphered_text)  
  
if __name__ == '__main__':
  customtkinter.set_appearance_mode('light')
  app = customtkinter.CTk()
  app.geometry('1000x460')
  app.title('Data Encryption Standard')

  input_label = customtkinter.CTkLabel(app, text='Input text', font=('Comic Sans MS', 20))
  input_label.place(x=20, y=10)
  input_text = customtkinter.CTkTextbox(app, font=('Comic Sans MS', 20), width=470, height=200)
  input_text.place(x=20,y=40)
  input_notifi = customtkinter.CTkLabel(app, text='', font=('Comic Sans MS', 20), text_color='red')
  input_notifi.place(x=150,y=10)

  output_label = customtkinter.CTkLabel(app, text='Output text', font=('Comic Sans MS', 20))
  output_label.place(x=510, y=10)
  output_text = customtkinter.CTkTextbox(app, font=('Comic Sans MS', 20), width=470, height=340)
  output_text.place(x=510,y=40)

  key_label = customtkinter.CTkLabel(app, text='Key', font=('Comic Sans MS', 20), fg_color='transparent')
  key_label.place(x=20,y=250)
  key_text = customtkinter.CTkTextbox(app, font=('Comic Sans MS', 20), width=470, height=20)
  key_text.place(x=20,y=280)
  key_notifi = customtkinter.CTkLabel(app, text='', font=('Comic Sans MS', 20), text_color='red')
  key_notifi.place(x=150,y=250)

  file_button = customtkinter.CTkButton(app, text='Choose file', font=('Comic Sans MS', 20), width=470, height=40, command=choose_file)
  file_button.place(x=20,y=340)

  encryption_button = customtkinter.CTkButton(app, text='Encrypt', font=('Comic Sans MS', 20), width=225, height=40, command=encrypt_button_clicked)
  encryption_button.place(x=20,y=400)

  decryption_button = customtkinter.CTkButton(app, text='Decrypt', font=('Comic Sans MS', 20), width=225, height=40, command=decrypt_button_clicked)
  decryption_button.place(x=265,y=400)
  
  save_button = customtkinter.CTkButton(app, text='Save file', font=('Comic Sans MS', 20), width=470, height=40, command=save_file)
  save_button.place(x=510,y=400)

  app.mainloop()