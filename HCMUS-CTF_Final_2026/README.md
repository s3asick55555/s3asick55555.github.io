# HCMUS-CTF Final 2026

We came at 7th place in this final, a little bit sad but it was worth it (it was also my first time to University of Science in the city).

## forensic

### a bun with friends 🥯🥟🫓🍞😋

#### Description

__Author__: jason

Let's go for a forensics challege with no artifacts :")

https://github.com/akusA-iahS/dangkyhocphan-HCMUS


#### Solution

__TL;DR__: A light variation of `Shai-Hulud` supply chain attack in Bun.js ecosystem, with heavily obfuscated scripts and data exfiltration using Telegram chat and GitHub repositories.

##### The attacker injected a malicious payload into the repository. What is the filename of the main payload script in the scripts/ directory? (Provide just the filename, e.g. 'index.js')

##### The attacker modified package.json to execute the payload automatically. Which npm lifecycle hook did the attacker add to trigger on 'npm install'? (Provide the hook name only, e.g. 'pretest')

##### A small wrapper script before loading the main payload. What is the full path of this wrapper, relative to the repo root? (Provide the path, e.g. 'src/index.tsx')

##### How many trigger point that run the malicious code? (Provide the number of trigger points, e.g. '1')

##### What pull request does the attacker inject malicious code? (Provide full PR URL, e.g. 'https://github.com/user/repo/pull/123')

##### The exfiltrated data is encrypted before being sent. What is the encryption scheme? (Provide the answer in format 'ALGORITHM-MODE', e.g. 'AES-128-CBC')

##### C2 Domain?

##### C2 endpoint path?

##### What compression algorithm is used to compress the plaintext before encryption? (Provide the algorithm name, e.g. 'rar')

##### What is the AWS key?

##### Vitim's hostname?

##### What was the time that the victim was first compromised?

#### Flag

`HCMUS-CTF{th1s_1z_th3_oRiginal_stuff_that_compr0miz3d_OpenAI_and_GitHub_but_m4d3_ez_n_fri3ndly_4_U_guyz}`


### Manifested

#### Description

__Author__: obiwan

Something seems wrong...

Handout: https://drive.google.com/file/d/1V2-OzRZWS46wCzwhhlnr0KhGuzZh4hft/view?usp=sharing

Unzip password: `a334f11699806041286d2c2fa439d433`


#### Solution

__TL;DR__: Attacker injected malicious Android code into a legimate app and using Firebase as a command-to-control (C2) server to control and exfiltrate data.

##### What is the package name of the payload injected into an app? (e.g. 'com.example.evil')

##### What is the State Or Province (ST) field of the APK's signing certificate?

##### Compared to the original clean APK, the repacked one declares exactly ONE extra permission. Which one? (e.g. 'ACCESS_FINE_LOCATION')

##### Before publishing its FCM token, the malware encrypts it with an RSA public. What is the filename of that public-key? (e.g. 'public.key')

##### The malware assigns each compromised device a unique id. What is the victim's UUID? (e.g. 'abcd1234-ef5')

##### The malware talks to a Firebase Realtime Database. What is the Firebase project-id it uses? (e.g. 'my-project-12345')

##### What is the fallback URL? (e.g. 'https://1.2.3.4:5000')

##### That's not the only node that is readable. Can you find the "secret" word?

#### Flag

`HCMUS-CTF{d1d_y0u_know_f1reb4se_could_b3_used_as_c2_1nfrastructur3_0n_Android}`