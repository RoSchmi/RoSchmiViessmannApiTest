RoSchmiViessmannApiTest

This is a 'quick and dirty' tool I implemented to learn how to use the Viessmann-Api to create Access Tokens and get Sensor-Values using the Viessmann Cloud API.

![gallery](https://github.com/RoSchmi/RoSchmiViessmannApiTest/blob/master/pictures/Viessmann_Api_Client.png)

How to use:
1) Enter the client_id in the text box in the left upper corner
2) Click the "Get Autorization Request Url" Button (marking the CheckBox will also retrieve a Refresh-Token)
3) Copy the created Url to the Clipboard
4) Paste the Url in the adddress bar of your internet browser and load the adressed page
5) On the opening page log in by entering your credentials
6) A new page opens in your browser
7) Retreive the delivered "Code" from the adress bar (string behind '?code=')
8) Copy and paste the "Code" in the textbox of this App
9) Click "Get Token(s)" (within 20 sec after step 4)
10) Copy the token to the Clipboard

Now you can use the created access token in requests to retrieve sensor-values from the Viessmann Cloud.
