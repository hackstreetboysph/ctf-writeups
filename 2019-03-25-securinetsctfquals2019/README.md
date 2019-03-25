# Securinets CTF Quals 2019

## Crypto

### Useless Admin

> solved by ameer

`Description: One member of our team, piece of sh#t an#s_boss, made a huge mistake using multi time pad. He knew that the OTP, if it is well applied, it is unbreakable. But this usesless brainless retard, went yoloooo. Not only that, but he deleted the original plain text, so we are screwed. The only thing left is the following file : cipher.json. It contains multiple cipher text, created using OTP and the same key. So can you figure out the plain text of the cipher_flag ? Flag format : Securinets{plain text here}`

This is a cryptography challenge about one-time pad (OTP). OTP is said to be uncrackable as long as you keep the messages short, use shorthand and abbreviations, remove unnecessary letters, never reuse a pad, and have a good enough random source for data.

The challenge gave us a `cipher.json` file which contains 11 instances of `cipher_list` and a `cipher_flag` all in hex format.

```
{
    "cipher_list": [
        "1b0605000e14000d1b524802190b410700170e10054c11480807001806004e4f1f4f01480d411400531158141e1c100016535a480c000c031a000a160d421e004113010f13451e0c0100100a020a1a4e165f500d0c1e041a090b001d0515521c0a0410000a4f4b4d1d1c184d071600071c0a521d1706540940",
        "1e10524e001f11481c010010070b13024f0704590903094d0c000e4f0711000615001911454217161a1a45040149000a5218404f1e0012060b1b590a1048171741140c01174c0d49174f0c8d4fc7520211531b0b0c1e4f",
        "1d0c04451352001a000154431b014109450a0a0b000045490403520a1d16490008535848085942071c0d0c57101c0045111c40430c4e111c0b1b1c451d4f071712010508475518061d00060a1b0a1a4c165d",
        "160d074300061d071b524e06190b134e450a0b0a4d4c12411d004f014045491b4649074804001100011d4504520612451e165d53064e164e1d060d0d44541a0041031b0b06540d1a070004001d4b074800531c04101d4f",
        "1a1d524912521548120045021b4e1506490a0859150345531d12521b4e094909030003011148420453074d161e05540b071e4c451b000a084a1d1c04084c0b45060b060a4742070618534218070210484512020043100e191e5956111a1c001c1f0b5c",
        "1a1d5248000154041a1c47430d0b04000005015900140c4f04534f094e08490103000000045442111b11001b1b1d000917535a48004e021d4a0e0b0044491c03080a001a024c11490748074f02040054451a1d150c1b150d020d0e",
        "1a1d5249125215481613500a1b0f0d4e4d0d1c0d000700001d1c001b06004f1d0f5a11480745040a011100181c0c540d13000e44085404404a061716014e010c0308104e084e0d4911450506011853540a5304120a1a154c0a1843001b45541c481607051b431f480d001e0400000c531d01011d00124441010200190d0800000000000e54060001100a1b4d0b040d105347",
        "0a0607000913020d551300041d0f0f0a0003061f154c034f1b53530602004e0c030c541f0454110a1d5a001e0649190419165d00104f104e1b1a101101001b0b1705051b0642040c5341114f0e4b104f0803110b0a060f42",
        "160d074300061d071b524e06190b134e450a0b0a4d4c12411d004f014045491b4649074804001100011d4504520612451e165d53064e16424a1810110c00060d04440e1c02411c0c00544209001953540d165009021a1542",
        "1e10524e001f11481c010010070b13024f0704590903094d0c000e4f0711000615001911454217161a1a45040149000a5218404f1e0012060b1b590a1048171741140c01174c0d49174f4201001f534b0b1c074b",
        "1a49134d4113540a0713490d434e160f541700174f4c11480c53520a1d1100000000190d4549114512544d12000c540402034b4e0d491d40"
    ],
    "cipher_flag": "1a4905410f06110c55064f430a00054e540c0a591603174c0d5f000d1b110006414c1848164516111f1100111d1b54001c17474e0e001c011f1d0a4b"
}
```

However, on this challenge something is wrong as same key was `reused` more than once - which I then used to break the encryption. The attack for this is called many time pad attack.

To understand how this attack works, below is a short explaination of it.

**Note:** ⊕ is bitwise xor operator. This symbol means to take the xor individually of each bit pair of the message.

For example, we have two messages (`C1` and `C2`), and you have a key (`K`).

For OTP encryption, you would simply do:

`C1 ⊕ K = Encrypted`

And that will encrypt the original message.

If you then send the `Encrypted` to someone, and given that they have the key, they would simply do:

`Encrypted ⊕ K = C1`

And that will give them the original message.

But in case we have:

`Encrypted1 = C1 ⊕ K and Encrypted2 = C2 ⊕ K`

Now this gets interesting, as we can XOR the two encrypted text together which will completely remove the key from the equation.

In short:

`Encrypted1 ⊕ Encrypred2 = C1 ⊕ K ⊕ C2 ⊕ K = C1 ⊕ C2`

All that is left for us is to guess a part of one of the messages, which would in turn give us the corresponding part of the other message.

In summary, in order to attack this encryption and uncover the secret plain text message, we would need to:

1. Guess a word that would probably appear in one of the messages
2. Encode the word into a hex string
3. XOR the two cipher text messages
4. XOR the hex string at each position of the XOR of the two cipher text
5. When the result is readable text, we guess the word and expand our crib search
6. If the result is not readable text, we try a XOR of the crib word at the next position

More details regarding this can be found on [taking advantage of one-time pad key reuse article](https://crypto.stackexchange.com/questions/59/taking-advantage-of-one-time-pad-key-reuse/).

Going back to the challenge, I didn't want to reinvent the wheels so I just used this available [many time pad attack script](https://github.com/Jwomers/many-time-pad-attack/raw/master/attack.py), then modified it to solve the challenge. 

**Solution:**

```
#!/usr/bin/env python 
# Solution for Useless Admin - Securinets CTF Quals 2019 
# Ameer Pornillos - https://ethicalhackers.club/ 
# Original code by Jwomers: https://github.com/Jwomers/many-time-pad-attack/blob/master/attack.py)
import string
import collections
import sets
import sys

# XORs two string
def strxor(a, b):     # xor two strings (trims the longer input)
    return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])

#11 cipher text from cipher_list
c1 = "1b0605000e14000d1b524802190b410700170e10054c11480807001806004e4f1f4f01480d411400531158141e1c100016535a480c000c031a000a160d421e004113010f13451e0c0100100a020a1a4e165f500d0c1e041a090b001d0515521c0a0410000a4f4b4d1d1c184d071600071c0a521d1706540940"
c2 = "1e10524e001f11481c010010070b13024f0704590903094d0c000e4f0711000615001911454217161a1a45040149000a5218404f1e0012060b1b590a1048171741140c01174c0d49174f0c8d4fc7520211531b0b0c1e4f"
c3 = "1d0c04451352001a000154431b014109450a0a0b000045490403520a1d16490008535848085942071c0d0c57101c0045111c40430c4e111c0b1b1c451d4f071712010508475518061d00060a1b0a1a4c165d"
c4 = "160d074300061d071b524e06190b134e450a0b0a4d4c12411d004f014045491b4649074804001100011d4504520612451e165d53064e164e1d060d0d44541a0041031b0b06540d1a070004001d4b074800531c04101d4f"
c5 = "1a1d524912521548120045021b4e1506490a0859150345531d12521b4e094909030003011148420453074d161e05540b071e4c451b000a084a1d1c04084c0b45060b060a4742070618534218070210484512020043100e191e5956111a1c001c1f0b5c"
c6 = "1a1d5248000154041a1c47430d0b04000005015900140c4f04534f094e08490103000000045442111b11001b1b1d000917535a48004e021d4a0e0b0044491c03080a001a024c11490748074f02040054451a1d150c1b150d020d0e"
c7 = "1a1d5249125215481613500a1b0f0d4e4d0d1c0d000700001d1c001b06004f1d0f5a11480745040a011100181c0c540d13000e44085404404a061716014e010c0308104e084e0d4911450506011853540a5304120a1a154c0a1843001b45541c481607051b431f480d001e0400000c531d01011d00124441010200190d0800000000000e54060001100a1b4d0b040d105347"
c8 = "0a0607000913020d551300041d0f0f0a0003061f154c034f1b53530602004e0c030c541f0454110a1d5a001e0649190419165d00104f104e1b1a101101001b0b1705051b0642040c5341114f0e4b104f0803110b0a060f42"
c9 = "160d074300061d071b524e06190b134e450a0b0a4d4c12411d004f014045491b4649074804001100011d4504520612451e165d53064e16424a1810110c00060d04440e1c02411c0c00544209001953540d165009021a1542"
c10 = "1e10524e001f11481c010010070b13024f0704590903094d0c000e4f0711000615001911454217161a1a45040149000a5218404f1e0012060b1b590a1048171741140c01174c0d49174f4201001f534b0b1c074b"
c11 = "1a49134d4113540a0713490d434e160f541700174f4c11480c53520a1d1100000000190d4549114512544d12000c540402034b4e0d491d40"

ciphers = [c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11]

# The target ciphertext we want to crack
target_cipher = "1a4905410f06110c55064f430a00054e540c0a591603174c0d5f000d1b110006414c1848164516111f1100111d1b54001c17474e0e001c011f1d0a4b"

# To store the final key
final_key = [None]*150
# To store the positions we know are broken
known_key_positions = set()

# For each ciphertext
for current_index, ciphertext in enumerate(ciphers):

	counter = collections.Counter()
	# for each other ciphertext
	for index, ciphertext2 in enumerate(ciphers):
		if current_index != index: # don't xor a ciphertext with itself
			for indexOfChar, char in enumerate(strxor(ciphertext.decode('hex'), ciphertext2.decode('hex'))): # Xor the two ciphertexts
				# If a character in the xored result is a alphanumeric character, it means there was probably a space character in one of the plaintexts (we don't know which one)
				if char in string.printable and char.isalpha(): counter[indexOfChar] += 1 # Increment the counter at this index
	knownSpaceIndexes = []

	# Loop through all positions where a space character was possible in the current_index cipher
	for ind, val in counter.items():
		# If a space was found at least 7 times at this index out of the 9 possible XORS, then the space character was likely from the current_index cipher!
		if val >= 7: knownSpaceIndexes.append(ind)
	#print knownSpaceIndexes # Shows all the positions where we now know the key!

	# Now Xor the current_index with spaces, and at the knownSpaceIndexes positions we get the key back!
	xor_with_spaces = strxor(ciphertext.decode('hex'),' '*150)
	for index in knownSpaceIndexes:
		# Store the key's value at the correct position
		final_key[index] = xor_with_spaces[index].encode('hex')
		# Record that we known the key at this position
		known_key_positions.add(index)

# Construct a hex key from the currently known key, adding in '00' hex chars where we do not know (to make a complete hex string)
final_key_hex = ''.join([val if val is not None else '00' for val in final_key])
# Xor the currently known key with the target cipher
output = strxor(target_cipher.decode('hex'),final_key_hex.decode('hex'))
# Print the output, printing a * if that character is not known yet
print ''.join([char if index in known_key_positions else '*' for index, char in enumerate(output)])

'''
Manual step
'''
# From the output this prints, we can manually complete the target plaintext from:
# The secuet-mes*age*is: Wh** usi|g **str*am cipher, nev***use th* k*y *ore than onc*
# to:
# The secret message is: When using a stream cipher, never use the key more than once

# We then confirm this is correct by producing the key from this, and decrpyting all the other messages to ensure they make grammatical sense
target_plaintext = "i wanted to end the"
print target_plaintext
key = strxor(target_cipher.decode('hex'),target_plaintext)
for cipher in ciphers:
	print strxor(cipher.decode('hex'),key)
print "\n===========\nRecovered key: "+key+"\n===========\n"
```

**Result:**

```
* *anted to ind t** y*rl*, but i'*l*settle for endin* ****s.
i wanted to end the
how often have i sa
my name is sherlock
never trust to gene
education never end
it is a great thing
it has long been an
it is a capital mis
you have a grand gi
education never end
my name is sherlock
i am a brain, watso

===========
Recovered key: sir arthur conan do
===========
```

By using the script and modifying the target plaintext value to match the correct words by guessing intelligently, would result on finding out that the target plaintext is a quote by `Sir Arthur Conan Doyle`.

`I wanted to end the world, but I'll settle for ending yours.`


Flag is:
```
Securinets{i wanted to end the world, but i'll settle for ending yours.}
```

**Fun Fact:** 
The moment the name appeared, I already knew how to complete the plaintext, as I'm a book reader of `The Adventures of Sherlock Holmes`, which is one of the notable works of the author.


