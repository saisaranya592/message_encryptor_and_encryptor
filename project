from tkinter import *
import base64
from tkinter import messagebox
import tkinter.font as font
import random
import string

# Encoding Function
def encode(key, msg):
    enc = []
    for i in range(len(msg)):
        list_key = key[i % len(key)]
        list_enc = chr((ord(msg[i]) + ord(list_key)) % 256)
        enc.append(list_enc)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

# Decoding Function
def decode(key, code):
    try:
        dec = []
        enc = base64.urlsafe_b64decode(code).decode()
        for i in range(len(enc)):
            list_key = key[i % len(key)]
            list_dec = chr((256 + ord(enc[i]) - ord(list_key)) % 256)
            dec.append(list_dec)
        return "".join(dec)
    except Exception as e:
        print(e)
        return None


# Function that executes on clicking Show Message function
def result():
    msg = message.get()
    k = inp_key.get()
    i = mode.get()
    
    if not msg:
        messagebox.showerror("Error", "Message cannot be empty.")
        return
    
    try:
        if i == 1:
            output.set(encode(k, msg))
        elif i == 2:
            output_text = decode(k, msg)
            if output_text is None:
                messagebox.showerror("Error", "An error occurred during decryption.....")
            else:
                output.set(output_text)
        else:
            messagebox.showerror('Please Choose one of Encryption or Decryption.......')
    except Exception as e:
        messagebox.showerror('An error occurred.        ')

# Function to generate a random password
def generate_password():
    length = pass_length_entry.get()
    if not length.isdigit():
        messagebox.showerror("Error", "Invalid length. Please enter a valid numeric value.")
        return
    length = int(length)
    special_characters = string.punctuation
    password = ''.join(random.choices(string.ascii_letters + string.digits + special_characters, k=length))
    pass_result_entry.delete(0, END)  # Clear any previous result
    pass_result_entry.insert(0, password)

# Function that executes on clicking Reset function
def reset():
    message.set("")
    inp_key.set("")
    mode.set(0)
    output.set("")
    pass_length_entry.delete(0, END)
    pass_result_entry.delete(0, END)

wn = Tk()
wn.geometry("500x550")
wn.configure(bg='lightgrey')
wn.title("Encrypt and Decrypt your Messages")

message = StringVar()
inp_key = StringVar()
mode = IntVar()
output = StringVar()

headingFrame1 = Frame(wn, bg="lightblue", bd=5)
headingFrame1.place(relx=0.2, rely=0.05, relwidth=0.6, relheight=0.1)

headingLabel = Label(headingFrame1, text="Encryption and Decryption",fg='black', font=('Arial', 14, 'bold'), bg='lightblue')
headingLabel.place(relx=0, rely=0, relwidth=1, relheight=1)

label1 = Label(wn, text='Enter the Message', font=('Arial', 10, 'bold'), bg='lightgrey')
label1.place(x=10, y=150)

msg_entry = Entry(wn, textvariable=message, width=35, font=('Arial', 10))
msg_entry.place(x=200, y=150)

label2 = Label(wn, text='Enter the key', font=('Arial', 10, 'bold'), bg='lightgrey')
label2.place(x=10, y=200)

key_entry = Entry(wn, textvariable=inp_key, width=35, font=('Arial', 10))
key_entry.place(x=200, y=200)

label3 = Label(wn, text='Choose encryption or decryption', font=('Arial', 10, 'bold'), bg='lightgrey')
label3.place(x=10, y=250)

Radiobutton(wn, text='Encrypt', variable=mode, value=1, bg='lightgrey').place(x=200, y=250)
Radiobutton(wn, text='Decrypt', variable=mode, value=2, bg='lightgrey').place(x=300, y=250)

label4 = Label(wn, text='Result', font=('Arial', 10, 'bold'), bg='lightgrey')
label4.place(x=10, y=300)

res_entry = Entry(wn, textvariable=output, width=35, font=('Arial', 10))
res_entry.place(x=200, y=300)

show_btn = Button(wn, text="Show Message", bg='lightgreen', fg='black', width=15, height=1, command=result)
show_btn['font'] = font.Font(size=12, weight='bold')
show_btn.place(x=180, y=350)

reset_btn = Button(wn, text='Reset', bg='orange', fg='black', width=15, height=1, command=reset)
reset_btn['font'] = font.Font(size=12, weight='bold')
reset_btn.place(x=15, y=350)

quit_btn = Button(wn, text='Exit', bg='red', fg='black', width=15, height=1, command=wn.destroy)
quit_btn['font'] = font.Font(size=12, weight='bold')
quit_btn.place(x=345, y=350)

# Password generation section
label5 = Label(wn, text='Enter Password Length', font=('Arial', 10, 'bold'), bg='lightgrey')
label5.place(x=10, y=400)

pass_length_entry = Entry(wn, width=10, font=('Arial', 10))
pass_length_entry.place(x=200, y=400)

pass_result_entry = Entry(wn, width=35, font=('Arial', 10))
pass_result_entry.place(x=200, y=430)

gen_pass_btn = Button(wn, text='Generate Password', bg='lightblue', fg='black', width=15, height=1, command=generate_password)
gen_pass_btn['font'] = font.Font(size=10, weight='bold')
gen_pass_btn.place(x=330, y=425)

wn.mainloop()
