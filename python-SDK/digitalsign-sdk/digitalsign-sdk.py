import requests

class Digitalsign:
    def __init__(self, baseurl):
        self.baseurl = baseurl

    def getDigitalsign(self, data):
        response = requests.post(f'{self.baseurl}/getdigitalsign', json=data)
        return response.json() 

    def verifyDigitalsign(self, data):
        response = requests.post(f'{self.baseurl}/verifysign', json=data)
        return response.json() 

if __name__ == "__main__":
    d = Digitalsign("http://127.0.0.1:8000")
    message = {"message": "request approved"}

    digisign = d.getDigitalsign(message) 
    print(digisign) 

    print("----------")

    verify=d.verifyDigitalsign(digisign)
    print(verify)




