# TP-Link core for C++
It didn't exist (i think), and now it does.

# Important notes
This is not pure C++. I'm using it for my ESP32 projects, so a little bit of the arduino library was used for HTTP requests.
You are welcome to fork it make it without arduino. \
\
Also, this is an *extremely* minimal implementation. There's no JSON parsing for requests or responses, you'll have to handle that with your favorite JSON parser :)
Furthermore, there is no handeling of re-getting cookies after they run out. A public attribute (cookieTimeout_s) is available for you to handle the cookie death how you would like

# How to use
Firstly, make sure you have a `credentials.cpp` (or linked `credentials.o`) available with the TP-Link account details in according to the header file specification

```cpp
int main()
{
    TPLinkCore core;
    core.deviceIP = "192.168.X.XXX"; // Change this
    
    // Ensure you are connected to the same network as the TP-Link device !!!
    
    // Last time I checked, a handshake lasts 1 day
    // You can handle the reshaking of hands however you please, I leave it up to you.
    if (core.handshake() != 0)
    {
        cout << "Handshake failed";
        return 1;
    }
    
    string response = core.sendRequest("{\"method\": \"set_device_info\", \"params\": {\"device_on\": true}}");
    cout << response << endl; // Would print {"error_code":0} upon success
    
    return 0;
}
```
