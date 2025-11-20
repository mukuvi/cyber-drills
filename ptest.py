#!/bin/python3

# print("hello kenya")
quote ="they will remember me not because of bad deeds or good deeds but because of the life i lived"

# print(quote.title())
# print(quote.lower())
# print(quote.upper())

age =22
name = "james"

# print(name + " is " + str(age) + " old")

### functions

def logs():
    file = "root"
    system = "Parrot OS"
   ##  print("I am using " +file+ " file in the "+system)
logs()

def soda(money):
    if money>5:
        return "Proceed to buy soda"
    else:
        return "Go home"
#print(soda(2))

def alcohol(age,money):
    if(age>=21) and (money>=5):
        return "Proceed to get yourself a tipsy"
    elif(age>=21) and (money<5):
        return "Come with more money"
    elif(age<21) and (money>=5):
        return "You cant have alcohol, too young"
    else:
        return "go home"
#print(alcohol(22,7))
#print(alcohol(21,4))

###lists

cars = ["cardillac","mercedes benz", "toyota","mazda","nissan","tesla"]

print(cars[1])
