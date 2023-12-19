# dread_pirate
## Challenge Description

**Category**: Networking

**Description**: We've got an agent on the inside and we've tapped his network...

![dread_pirate_description_img](https://github.com/Om3rR3ich/CTF-Writeups/assets/88339137/8f115fcd-2327-4bb9-8e60-2425af60374e)

This challenge is a classic of the networking category - you're given a packet capture that was sniffed from somewhere and you need to use it to find important information
(i.e. the flag or something that leads you to it). Other than the capture file (dpr.pcapng), no information or background was provided. That had contributed to the mysterious
and explorative nature of the challenge.

## Wireshark Analysis
"When all you have is a capture file, everything looks like Wireshark"
Well, that's not really how the saying goes, but Wireshark is indeed the all-nail-hitting-hammer when it comes to analyzing network traffic.
Opening dpr.pcapng in Wireshark, the screen becomes bloated with information:

![wireshark_initial_screen](https://github.com/Om3rR3ich/CTF-Writeups/assets/88339137/424d6e73-14d0-49ae-8c03-f6ef90aeb20d)

As you may know, even short interactions and simple actions create a lot of traffic, so going through the packets one by one isn't feasible (and is excruciatingly slow).
The first thing I usually look for is HTTP traffic, usually the important stuff will be there - what websites were accessed and what actions were performed.
If you're lucky, an old website might use HTTP (instead of HTTPS, although in both cases the network protocol will be HTTP) so the data is not encrypted.
Here, however, not a single HTTP packet is found (in retrospect, ALL of the IP addresses in the capture are private addresses, so everything's happening on a private network, so I shouldn't have expected computers to access websites) . It looks like the traffic is made up of mainly TCP and VNC (VNC is a TCP protocol, but it's still worth special treatment as you'll soon see).
I wasn't familiar with the VNC protocol at all before this challenge, so I looked it up (this is just a friendly reminder that it's perfectly normal not to know everything and learn stuff during a CTF. Don't be afraid to learn something on the fly and apply it immediately - it may even work :) ).

## VNC
It's basically responsible for transmitting information about a user's action through the VNC program.
Well, perhaps I need to go back a little. VNC (Virtual Network Computing) is a program that allows one computer control another one, provided they're both connected to the same network.
VNC is also the name of the network protocol that transmits the actions of the controlling computer to the controlled computer. It also shows the controlling computer
the controlled computer's screen by trasmitting chunks of a screenshot (JPEG image) to the controlling computer. This will be (very) important later.
Fortunately, Wireshark has a very user-friendly interface to examine VNC packets. Here's an example of one interaction that I found after searching for the string "flag" (it was a little harder than that XD)
in the VNC packets:

![wireshark_vnc_cut](https://github.com/Om3rR3ich/CTF-Writeups/assets/88339137/548f7a9a-8d1a-472e-a905-ba0f65a6cf05)

Notice the properties in the Virtual Network Computing layer of the packet (bottom left of the image).

The problem is, even after filtering for VNC packets, there is still too much data to go through manually.

## Keylogging?
One interesting direction is to find the packets that are responsible for keyboard events. Wouldn't it be awesome to know everything the victim typed?

There's also a ~~decent~~ nonzero chance he typed the flag...
You can use the `vnc.key_down` filter in wireshark to look the the key presses.
It's important to use `key_down` rather than just `key`, because `key` would account
for the `key_up` events which are just releases of keys, so you'll get every keypress twice.

Since there are many `key_down` packets, this screams for automation.
`scapy` is a neat Python library that helps managing packets (sending, receiving, sniffing, and analyzing them). Although `scapy` is great, it's not as user-friendly as 
Wireshark - I can't simply filter by `key_down` packets!

To really achieve automation here, I needed to understand the structure of these packets so I can filter them myself.
Let's have a closer look at this type of packets (the following example is the first one of them, it stands for pressing the key 'w'):

![wireshark_first_key_event](https://github.com/Om3rR3ich/CTF-Writeups/assets/88339137/a185fbb6-8674-4702-b57f-ef898314fbb6)

As you can see, there's not really an obvious (at least at a first glance) connection between the VNC properties and the raw bytes (shown in hex).
For this reason, I spent some time in a silly "find the differences game" between key events and mouse events, and especially key_down events vs key_up events.

I assumed there's some binary flag that determines which one it is, and I was right - I marked the relevant byte in blue in the above image. If this byte is 1, it's a key_down, otherwise - a key_up.

In a similar fashion I discovered that all key events had a 04 byte right before the previous (marked) byte I was referring to.

Lastly, the value of the key pressed is held in the last four bytes of the packet's payload. I only cared about ASCII characters (you can guess when Enter, Shift, etc were used and I was too lazy to make a mapping between the special keys and their respective codes),
so I could save just the last byte. Based on the above information, dumping the keystokes is simple (I'm not going to go over how to use `scapy` here, because that's not the goal of this writeup and the syntax is fairly intuitive):

```python
from scapy.all import *

packets = rdpcap('dpr.pcapng')

typed_text = bytearray(b'')

for pkt in packets:
	if pkt.haslayer(Raw):
		load = pkt[Raw].load
		
		# key event (first byte in the payload is 04)
		if load[0] == 4:
			# key down event (the down/up flag is set to 01)
			if load[1] == 1:
				typed_text.append(load[-1])

print(typed_text)
```

\* It's worth noting that the packet structure analysis can be done easily within Wireshark - just click on the desired peroperty and it'll mark the bytes that control its value.
  If only I knew that when I originally solved the challenge!

Running the script results in the following output:
```python
bytearray(b'weecat\r/server add silk irc/6667\r/connect silk\r/i\x08nick drerd\r2you dii bitcoin exchange before you worke d\x08\x08d fr me  ig\x00t\xe1? \rnot any more then\xe1?  damn regulators, eh\xe1? \rokay which post\xe1? \r')
```
*Notice the "garbage bytes" - these were originally codes of special keys of which I trimmed the last byte.

Hmmmm, this is some fairly interesting information. It looks like two users ('weecat' and 'nick dred') are communicaing via IRC, but the conversation seem to halt prematuerly.
In addition, the last question (which post?) immediately reminded me of the previously cut text ("can you check out one of the flagged messages for me?").

Surely they're referring to the flag, right?

It's so unfortunate that there's no more information... But maybe not all hope is lost.

## Exploring IRC (the black hole that is port 6667)
At this point we know the juicy stuff is communicated via IRC, which goes through port 6667.
Filtering for TCP packets on port 6667, a hellish sight unfolds:

![wireshark_tcp_port_6667](https://github.com/Om3rR3ich/CTF-Writeups/assets/88339137/2b7226f6-7930-4a6c-b841-8c485aafc96c)

I'll save you the trouble, there's no recoverable information from this mess - it looks like (almost) every single packet had one error or another.
So, what now?

## JPEGs hidden in plain sight
Remember how VNC transmits screenshots in JPEG "chunks" (i.e. small portions of the image, not the usual meaning of chunk in an image file)?
Since everything else seemed to be a dead end, I figured I should have a look at that. Now, I can guess what you're thinking - how the hell is it possible to stare at
the packets for so long and not notice all of these JPEG headers?

Well, I did notice them, but initially thought they were corrupted because they lacked a consistent ending (footer).
Apparently, [there's no footer in the JPEG format](https://stackoverflow.com/questions/4999528/jpeg-footer-read).

Anyway, I tried to use `binwalk` to extract the images, but for whatever reason it failed to extract them (it did detect them correctly). Luckily, there are alternatives
to `binwalk`, for instance, `foremost`. 

`foremost dpr.pcapng` worked just fine, and extracted all (400+) of the images.

Browsing through the images, I noticed that while many of them were too small to supply any menaingful information, some actually showed snippets of the IRC chat!
Piecing together the images (in my mind, I didn't bother converting them to bigger, complete images), I noticed messages that I've seen before - in the result of the keystrokes dumper script.

It looks like some of the packets were lost, because some letters were indeed missing. 'weecat' is not a silly username - it's actually 'weechat' ('h' was probably lost in trasmittion) -
the platform that was used for the communication (you can run it as a command in linux). Also, the second user isn't 'nick dred', but 'nick **dread**'! 
Just like the challenge's description.

After doing that for a while, I made an educated guess that the flag will appear near the end of the communication.
Looking at the images in reverse order (from the last one to the first), I quickly found the flag, right there in the IRC chat:

![flag_message_irc](https://github.com/Om3rR3ich/CTF-Writeups/assets/88339137/177eaf2c-d9be-4e29-a5e7-fe6c51d1e214)

That's the flag!

`flag{knock_knock_open_up_its_the_fbi}`

You may wonder why the flag didn't show up in the result of the keystrokes dump. 
The most plausible explanation I can think of is that another person (not the one who's controlling the computer over VNC) typed this message.

## Addendum
Networking, as a subject, tends to be greyer than a group of mice (apparently called a 'mischief') covered in gravel on a winter day (i.e. boring).

However, this challenge, although frustrating, was actually fun to solve. It puts the player in a detective role,
and challenge feels like an adventure (rather than an endless day at an office, doing the type of work that makes you burn out after a year, which is how most networking related tasks are).

In my opinion, the lesson here is that adding backstory (even just a little, like the "nick dread pirate" thing) to challenges makes them much more interesting and rewarding to solve,
and also, not to judge a CTF challenge by its category ;)

*Writeup by Om3rR3ich*
