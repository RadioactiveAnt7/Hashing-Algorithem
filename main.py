
import random
class Password:
    def __init__(self, password,salt = None):

        self.hashCharacters = ([str(i) for i in range(10)] +
                               [chr(ord('a') + i) for i in range(26)] +
                               [chr(ord('A') + i) for i in range(26)] +
                               ['+', '/', '=', '@', '#', '$', '%', '&', '*', '!', '-', '_'])
        self.hashCharactersLength = len(self.hashCharacters)
        if salt == None:
            self.salt = self.getSalt(32).upper()
        else:
            self.salt = salt
        self.hashedPassword = self.Hash(password)[30:94].upper()
    @staticmethod
    def checkPassword(password,hashedPassword,salt):
        return Password(password,salt).hashedPassword == hashedPassword
    def getSalt(self, length):
        salt = ""
        for i in range(length):
            salt += self.hashCharacters[random.randint(0, self.hashCharactersLength - 1)]
        return salt

    def shortenString(self, string):
        result = ""
        for i in range(len(string)):
            if i % 2 == 0:
                result += string[i]
        return result
    def singleHash(self, password):

        hashedPassword = "".join(str(ord(ch)) for ch in password)
        characterSet = [i for i in range(145)]
        for splitAmount in range(3, 12):
            hashedPassword = "".join(
                [self.baseChanger(i, characterSet) for i in self.splitNumber(hashedPassword, splitAmount)])


        intSalt = self.reverseBaseChanger(self.salt, self.hashCharacters)
        hashedPassword = str(abs(int(hashedPassword) - intSalt) * intSalt)
        for splitAmount in range(5, 10,2):
            hashedPassword = "".join(
                [self.baseChanger(i, characterSet) for i in
                 self.splitNumber(hashedPassword, splitAmount)])

        return hex(int(hashedPassword))

    def Hash(self,password):# hashed the password many times
        hash = self.singleHash(password)
        for i in range(5):
            hash = self.singleHash(hash)
        return hash

    def baseChanger(self, number, digits):# base changer to change any number to any base with an inputed character set.

        number = int(number)
        if number == 0:
            return str(digits[0])

        base = len(digits)
        result = ''
        while number > 0:
            remainder = number % base

            result = str(digits[remainder]) + result
            number //= base

        return result

    def reverseBaseChanger(self, input_str, digits):

        base = len(digits)
        result = 0
        input_str = input_str[::-1]  # Reverse the input string to start from the least significant digit

        for i, char in enumerate(input_str):
            digit = digits.index(char)
            result += digit * (base ** i)

        return result

    def splitNumber(self, number, num_parts=5):
        # Calculate the length of each part
        partLength = len(number) // num_parts

        numberParts = []

        # Split the large number into 'numberParts' roughly equal parts and append them to the array
        for i in range(0, len(number), partLength):
            part = number[i:i + partLength]
            numberParts.append(part)
        return numberParts


JacksPassword = Password("Enter your password here","C$RGB3RLN4PFSF1E11DXZB6@U3TAH$8S")
print(JacksPassword.hashedPassword)# add to database
print(JacksPassword.salt) # add to database

#the salt is random and should only be generated once when the user is created
#below is an example of a hashed password and salt that should be stored in a database
hashedPasswordMade = " F3EAABBD479F322DAFD3E237D721EA42206481842144D6E4FDE907DA5D648F1A"
saltMade = "C$RGB3RLN4PFSF1E11DXZB6@U3TAH$8S"

#these are the salt and hashed password you get from the database when the user enters there username
salt = "C$RGB3RLN4PFSF1E11DXZB6@U3TAH$8S" # salt from database
hashedPassword = "F3EAABBD479F322DAFD3E237D721EA42206481842144D6E4FDE907DA5D648F1A" # hashed Password from database

#this function will return True to False depending on if the password is correct
print(Password.checkPassword("Enter your password here",hashedPassword,salt))

