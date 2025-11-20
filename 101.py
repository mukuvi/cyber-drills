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

#print(cars[1])
#print(cars[0:4])
#print(cars[:1])
#print(cars[1:])
#print(len(cars))
cars.append("bmw") #add item to list
cars.pop() #delete last item from the list
cars.pop(3) #delete specific item in the list

cities = ["eldoret","nairobi","mombasa","kisumu","nakuru"]
towns = ["machakos","kitale","thika","garisa","iten"]
combined = zip(cities,towns)
# print(list(combined))

###Tuples - cannot  change and use parenthesis
grades = ("A","B","C","D")
#print(grades[2])

###Looping
fruits = ["mango","banana","apple","orange","pineapple"]

for x in fruits:
   # print(x)
i= 1
while i<10:
    print(i)
    i+=1

