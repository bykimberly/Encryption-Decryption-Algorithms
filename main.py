import random
import math
import affineRSA

print("-- Welcome to the Encryption/Decryption Tester --")

while True:
  user_in = input(
      "\n" + "-" * 50 +
      "\nWhich problem would you like to test?\n1.  Problem 1: affine_encrypt(text, a, b)\n2.  Problem 2: affine_decrypt(cipher, a, b)\n3.  Problem 3: encryptRSA(text, n, e)\n4.  Problem 4: decryptRSA(cipher, p, q, e)\nQ.  Quit\n\nEnter your selection: "
  )

  if user_in == '1':
    print("\n" + "-" * 50 + "\n\nTesting Problem 1...\n\n")

    expected1 = 'INOTTOZZSNKOJ'
    received1 = affineRSA.affine_encrypt('STOP POLLUTION', 5, 22)
    print(
        f"Testing affine_encrypt(\"STOP POLLUTION\", 5, 22)....\n\tExpected: {expected1} \n\tReceived: {received1}"
    )

    if expected1 == received1:
      print("\tTest PASSED!")
    else:
      print("\tTest FAILED.")

    expected2 = 'WGVXFCVO'
    received2 = affineRSA.affine_encrypt("BLACK HAT", 1, -31)
    print(
        f"\nTesting affine_encrypt(\"BLACK HAT\", 1, -31)....\n\tExpected: {expected2} \n\tReceived: {received2}"
    )

    if expected2 == received2:
      print("\tTest PASSED!")
    else:
      print("\tTest FAILED.")

    print(
        f"\nTesting affine_encrypt(\"SOME MESSAGE\", 2, 3)...\n\tExpected: ValueError"
    )
    try:
      received = affineRSA.affine_encrypt("SOME MESSAGE", 2, 3)
      print("\tReceived:", received)
      print("\tTest FAILED.")
    except ValueError:
      print("\tRaised ValueError.\n\tTest PASSED!")

  elif user_in == '2':
    print("\n" + "-" * 50 + "\n\nTesting Problem 2...\n\n")

    expected1 = 'STOPPOLLUTION'
    received1 = affineRSA.affine_decrypt('INOttOZZSnKOJ', 5, 22)
    print(
        f"Testing affine_decrypt('INOttOZZSnKOJ', 5, 22)....\n\tExpected: {expected1} \n\tReceived: {received1}"
    )

    if expected1 == received1:
      print("\tTest PASSED!")
    else:
      print("\tTest FAILED.")

    expected2 = 'BLACKHAT'
    received2 = affineRSA.affine_decrypt('WGVXFCVO', 1, -31)
    print(
        f"\nTesting affine_decrypt('WGVXFCVO', 1, -31)....\n\tExpected: {expected2} \n\tReceived: {received2}"
    )

    if expected2 == received2:
      print("\tTest PASSED!")
    else:
      print("\tTest FAILED.")

  elif user_in == '3':
    print("\n" + "-" * 50 + "\n\nTesting Problem 3...\n\n")
    texts = ['STOP', 'HELP', 'STOPS', 'REPEAT']
    expected = ['20812182', '09810461', '208121821346', '194319342299']

    for i in range(len(texts)):
      cipher = affineRSA.encryptRSA(texts[i], 2537, 13)
      print(
          f"Testing encryptRSA({texts[i]}, 2537, 13)\n\tReceived: {cipher}\n\tExpected: {expected[i]}"
      )
      if cipher == expected[i]:
        print("\tTest PASSED!\n")
      else:
        print("\tTest FAILED.\n")

  elif user_in == '4':
    print("\n" + "-" * 50 + "\n\nTesting Problem 4...\n\n")
    expected = ['STOP', 'HELP', 'STOPSX', 'REPEAT']
    ciphers = ['20812182', '09810461', '208121821346', '194319342299']

    for i in range(len(ciphers)):
      text = affineRSA.decryptRSA(ciphers[i], 43, 59, 13)
      print(
          f"Testing decryptRSA({ciphers[i]}, 43, 59, 13)\n\tReceived: {text}\n\tExpected: {expected[i]}"
      )
      if text == expected[i]:
        print("\tTest PASSED!\n")
      else:
        print("\tTest FAILED.\n")

  elif user_in.upper() == 'Q':
    break
  else:
    print("Invalid selection.  Please try again.")
