english_freq = [
    0.082,  # a = 0
    0.015,  # b = 1
    0.028,  # c = 2
    0.043,  # d = 3
    0.127,  # e = 4
    0.022,  # f = 5
    0.020,  # g = 6
    0.061,  # h = 7
    0.070,  # i = 8
    0.002,  # j = 9
    0.008,  # k = 10
    0.040,  # l = 11    
    0.024,  # m = 12
    0.067,  # n = 13
    0.075,  # o = 14
    0.019,  # p = 15
    0.001,  # q = 16
    0.060,  # r = 17
    0.063,  # s = 18
    0.091,  # t = 19
    0.028,  # u = 20
    0.010,  # v = 21
    0.023,  # w = 22
    0.001,  # x = 23
    0.020,  # y = 24
    0.001,  # z = 25
]

def freq_count(text):
    clen = len(text)
    counts = [0] * 26

    if text.isupper():
        shift = 65
    else:
        shift = 97

    # iterate thru text, count how many of each letter
    for c in text:
        int_value = ord(c) - shift
        counts[int_value] = counts[int_value] + 1
    
    # iterate thru array of counts
    for i in range(len(counts)):
        if counts[i] > 0:
            # divide each count by length of text to get frequency
            counts[i] = round(counts[i] / clen, 3)

    return counts

# calculate index of coincidence given a ciphertext message
def ic(ciphertext):
    freq = freq_count(ciphertext)
    i_of_c = 0
    for i in freq:
        # square each frequency
        i = (i ** 2)
        i_of_c = i_of_c + i

    return round(i_of_c, 3)

# calculate key length
def key_len(ciph):
    # find the key length | try each key length
    length = len(ciph) // 3

    avg_ics = [0] * length

    for k in range(1, len(ciph) // 3):
        # break ciphertext into k substrings
        substrings = ["" for i in range(k)]

        # put each character in its appropriate substring
        for j in range(len(ciph)):
            substrings[j % k] = substrings[j % k] + ciph[j]

        # init array to store index of coincidence values for each substr
        sub_ics = [0 for i in range(len(substrings))]
        total = 0

        # calculate IC for each substring
        for i in range(len(substrings)):
            sub_ics[i] = ic(substrings[i])
            total = total + sub_ics[i]
        
        # average IC for substrings
        avg = total / len(sub_ics)
        avg_ics[k] = avg
    
    max = 0
    # iterate through avg ics
    # pick out the key length
    for a in range(len(avg_ics)):
        if avg_ics[a] > max:
            max = avg_ics[a]
        elif avg_ics[a] < max:
            if a == len(avg_ics) - 1:
                break
            elif avg_ics[a + 1] < max:
                break
    
    return avg_ics.index(max)

# choose the highest MIC to get the key for that subtext
# return key as a string, all caps
def find_key(ciph, key_len):
    # divide ciphertext into key_len different substrings
    substrings = ["" for i in range(key_len)]
    subs_freq = [ [0]*26 for i in range(key_len)]
    
    for j in range(len(ciph)):
        substrings[j % key_len] = substrings[j % key_len] + ciph[j]

    # for each substring, count frequencies of each letter
    for f in range(key_len):
        for c in substrings[f]:
            subs_freq[f] = freq_count(substrings[f])
    
    # compute English freq arrays for each key/shift value
    english_freq_shifted = [ [0]*26 for i in range(26)]
    for shift in range(26):
        for e in range(len(english_freq)):
            i = english_freq[e]
            n = (e + shift) % 26
            english_freq_shifted[shift][n] = i

    mics = [ [0]*26 for i in substrings ]

    key_vals_intreps = []

    # for each possible key/substring combo, compute MIC with English freq shifted by that key
    for s in range(len(substrings)):
        for h in range(len(english_freq_shifted)):
            mics[s][h] = mic(subs_freq[s], english_freq_shifted[h])

        # output MICs
        print(mics[s])
        print()

        max_ind = mics[s].index(max(mics[s]))
        key_vals_intreps.append(max_ind)
    
    # convert key value int representations to letters
    key = ''
    for k in range(len(key_vals_intreps)):
        letter = chr(key_vals_intreps[k] + 65)
        key = key + letter

    return key


# calculate mic given frequency array of ciphertext and frequency array of english lang
def mic(ciph_freq, english_freq_shifted):
    m = 0
    for i in range(26):
        n = ciph_freq[i] * english_freq_shifted[i]
        m = m + n

    return round(m, 3)


# decrypt the ciphertext message
def vig_decrypt(ciph, key):
    plaintext = ''
    l = len(key)
    key_ind = 0

    for i in ciph:
        # get the int value for the given ciphertext character
        e = ord(i) - 65
        
        # find the appropriate letter/shift value in key to decrypt character
        k = ord(key[key_ind]) - 65

        # compute decrypted letter's integer value
        d_int = (e - k + 26) % 26  
        # convert to character & append to plaintext string
        d_chr = chr(d_int + 97)
        plaintext = plaintext + d_chr

        if key_ind == len(key) - 1:
            key_ind = 0
        else:
            key_ind = key_ind + 1

    return plaintext


def check_correctness(plaintext):
    # compute MIC of plaintext & english freq
    plaintext_freq = freq_count(plaintext)
    m = mic(plaintext_freq, english_freq)
    answer = ""

    if (abs(0.065 - m) <= 0.025):
        print("The above plaintext has a mutual index of coincidence of ", m, " when compared with natural english frequencies, so it is likely correct.")
    else:
        print("The above plaintext has a mutual index of coincidence of ", m, " when compared with natural english frequencies, so it may be incorrectly decrypted.")

# user inputs ciphertext
# ciph = str(input("input ciphertext:"))
ciph = "MWVAYWRMJUUQIPDHNXYGAYZRVPTSAPVBJHGBHLJGWDZNVGWMTNBZIGJJPKWHDEGDUCSAJBFLBKGCIDLHNRQLSWGIRFWUUUWTTRDINMHDXPIQBKGKAVTWJIKPFKXMYXHQPBEVCIDLDVRKQHWMKIFUKNIXCAGBBCKIKPWUBYYRECHXNDHTTWUBZKICGOBODMATFMHIVCPQEMWVAYWRKQLQVYFYNJNCMYIDMOZBOPWIVYINEDUPGOMOQGYRKBNTCIDDSSEWHOQJZEKMOMNAQIAEKTEDOFWZRTXOYSTEJPQKIRRZVKCBSBFNPPIPFGJBAZBXBUIVHTTTKOJUEXTRGZCHWTBODEWACIDUWZKIUYIDSMJDOFURHREXPDEBHZQVUOVHCKNFAMCIDMGFJDQCCGCIDAJNAPYSMKTGHQYZNACJGYKMETTPQMFMFBADQLPWGWLGICWMZHZRAQWRZNPCQ"
k = key_len(ciph)
key = find_key(ciph, k)
plaintext = vig_decrypt(ciph, key)

print("Key length: ", k)
print("Key: ", key)
print()
print("The decrypted plaintext: ", plaintext)
print()

check_correctness(plaintext)