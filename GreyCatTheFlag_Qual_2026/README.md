# Grey Cat The Flag 2026 Qualification

## Forensic

### APTV3R4_STRIKES_AGAIN

#### Solution

- Download the memdump at http://challs.nusgreyhats.org:35667/?download=mem_dump.dmp&token=PV6QKm8XtToPXK4G4u9uatWRX9GQlERnawgC31Uj5qb8KypnHVzPpNusmb84GdDvJZq
- Read it in Volatility 3, symbol is `Linux version 6.19.14+kali-amd64 (devel@kali.org) (x86_64-linux-gnu-gcc-15 (Debian 15.2.0-17) 15.2.0, GNU ld (GNU Binutils for Debian) 2.46) #1 SMP PREEMPT_DYNAMIC Kali 6.19.14-1+kali1 (2026-05-05)`
- Identify the Python PID (2433), extract the process memory
- Dump the script using `strings` and `grep`:
```py
# noisy_vault.py
import os
import time
import random

buffers = []
# Random high-entropy junk
for _ in range(250):
    buffers.append(os.urandom(1024 * 1024))  # 250 MB
# Decoy filenames and fake secrets
for i in range(1000):
    fake = f"""
    /tmp/keyfile_{i}.txt
    /opt/vault/flag_{i}.enc
    FAKE_KEY_{os.urandom(16).hex()}
    grey{{fake_flag_{i}}}
    """.encode()
    buffers.append(fake * random.randint(5, 30))

# Real encrypted flag only
with open("flag.enc", "rb") as f:
    flag_enc = f.read()
buffers.append(b"BEGIN_REAL_ARTIFACT_flag.enc\n" + flag_enc + b"\nEND_REAL_ARTIFACT\n")
print("Vault process running. PID:", os.getpid())
time.sleep(999999)
```

- Find the encrypted flag using this string `BEGIN_REAL_ARTIFACT_flag.enc` and `END_REAL_ARTIFACT`
- Extract the encrypted flag (it is OpenSSL encrypted with salt) to flag.enc
- Return to pcap file and extract the SMB hash:
```
APT::WORKGROUP:de4223bdc2c58d00:29b10ec063eabb61b9e426ed94ff89b1:01010000000000006a4d9cccdbeddc01c80030cc79b2db8200000000020022005400520049005600490041004c002d0054004f002d00560045005200490054005900010022005400520049005600490041004c002d0054004f002d005600450052004900540059000400000003001c007400720069007600690061006c002d0074006f002d00610070007400070008006a4d9cccdbeddc010600040002000000080030003000000000000000000000000000000019c57cf48a48b5f9532f68132492f004f1347993c6214b9482bb6ff9936db4930a001000000000000000000000000000000000000900260063006900660073002f003100340033002e003100390038002e00390034002e0031003200340000000000
```

- Crack it with Hashcat/John the Ripper -> get the password of `mypassword`
- Set the NTLMSSP password with `mypassword` -> Get the `keyfile.txt` (fa317cdb5f898ad01089b5432464052def12721f7f30f5c13d0af1f8b03e5295)
- Using OpenSSL to decrypt it

```
openssl enc -d -aes-256-cbc -in flag.enc -out flag.dec -pass pass:fa317cdb5f898ad01089b5432464052def12721f7f30f5c13d0af1f8b03e5295 -pbkdf2
```

Flag: `grey{7r1v14l_70_f0ll0w_7h3_5mb3_7r41l}`

### Crimewatch

```
1. Which TeleChat account or chat appears to be supplying the courier with vape stock?
2. What car plate number connected to the supplier's import method is recoverable from deleted image/cache evidence?
3. Which TeleChat contact appears to be the most recent buyer awaiting a delivery?
4. What coordinates identify the pickup point?

Answer format:
- TeleChat handles include the leading @
- Plate numbers are uppercase with no spaces
- Buyer must be lowercase plain text
- Coordinates use decimal latitude,longitude rounded to 2 decimal places
```

#### Solution

- Decrypt the Android FBE with `https://github.com/SlugFiller/fbe-decrypt/blob/master/fbe-decrypt.mjs`
- Load it in FTK Imager/Autopsy

##### Which TeleChat account or chat appears to be supplying the courier with vape stock?

In the `/system_ce/0/notification_history.xml`:

```xml
<?xml version="1.0" encoding="utf-8" ?> 
<notification-history>
  <notification package="com.grey.telechat" time="2026-05-14T16:49:00+08:00" title="@vanta_supply" text="same SG673... import pic attached" conversation="Vanta Supply" /> 
  <notification package="com.grey.telechat" time="2026-05-14T18:46:00+08:00" title="jiawei" text="im here already" conversation="jiawei" /> 
  <notification package="com.grey.telechat" time="2026-05-13T20:11:00+08:00" title="niko" text="settled ytd, mint was ok" conversation="niko" /> 
  </notification-history>
```
TeleChat handles include the leading @, so the answer would be `@vanta_supply`

##### What car plate number connected to the supplier's import method is recoverable from deleted image/cache evidence?

In the `/media/0/Pictures/TeleChat` there are 2 pictures, one of which is `IMG_20260514_164900.png`, with include the plate number (image was too heavy to be put here, so only the plate number is shown):

![image](https://hackmd.io/_uploads/HywLJHYeMl.png)

The plate number is `SG67301K`

##### Which TeleChat contact appears to be the most recent buyer awaiting a delivery?

According to the `/system_ce/0/notification_history.xml`, user `jiawei` appeared to be the most recent user (2026-05-14T18:46:00+08:00), therefore `jiawei` is the answer

##### What coordinates identify the pickup point?
The other image is `spot.jpg`:

![spot](https://hackmd.io/_uploads/HkHPyBYgGe.jpg)


Reverse image search on Google shows that this is Singapore Zoo, which locates at `1.4044021,103.7921862`.

Since coordinates use decimal `latitude,longitude` rounded to 2 decimal places, the answer is `1.40,103.79`

The final answer is `@vanta_supply SG67301K jiawei 1.40,103.79`, when inputs to the `flag.py` we got the flag:

```sh
python flag.py @vanta_supply SG67301K jiawei 1.40,103.79
[+] grey{tobacco_and_vaporisers_control_actdf269}
```