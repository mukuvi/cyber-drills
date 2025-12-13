#!/bin/bash
## importing
import sys # importing system function and parameters

from datetime import datetime
#print(datetime.now())
from datetime import datetime as dt #importing with alias
# print(dt.now())

## Advanced strings
my_name = "James Ngandu"
#print(my_name[0:5])
sentence = " just keep pushing boyy"

# print(sentence.split()) #split sentence by a delimeter
too_much_space = "hello          james      ngandu"
#print(too_much_space.strip())
full_name ="Julia Ngandu"
# print(full_name.replace("Julia","James"))

### place holders

car = "Mercedes Benz"
#print("My favorite car is {}".format(car))

### Dictionaries -are keys and values
drinks = {"Monster Energy":5, "Red Bull":6, "Predator":3}
employees = {"Finance":["Bob","Mary","Tina"], "IT":["James","Julia","Gene"], "HR":["Reuben","Lisa"]}
# print(employees)
employees["Legal"] = ["Mr. Franc"] # add new keys: value pair
print(employees)

names ={"science":["patrick","shadrack","shikuku"],"engineering":["ashford"]}
print(names["science"])

