# Cisco ASA Collector and Parser
<p>Author: Jason Ray Norris</p>
<br>
Follow me on YouTube:https://www.youtube.com/channel/UC-juxWFp_IXOcc4qp2dn-vw

<h4></h4>
<hr>
<h5>DISCLAIMER: This is AS-IS code. Until further notice, use at your own risk.</h5>

<hr>
<b>Description:
I wrote this back in 2017.  From memory this tested and worked on ASA code from 8.x to 9.0.
I used this in a Django framework with MariaDB backend.  

<br>These modules should run independently. You will need to take the collector data object and pass it into the parser.
</b>
<hr>
<br>
At a high level, this should accomplish the following:(it may require some tweaking)
<br>
<pre>
    1. (collector.py)Connect to an ASA via ssh.
    2. (collector.py)Pull config from device to local application memory.
    3. (parser.py)Pass collector data object into parser to parse configuration for application object representation.
    4. (parser.py)Parse access lists and object groups to a normalized a non-nested representation.
</pre>

I used this on greater than 100,000 lines of ASA firewall config. 
<br>*THERE ARE A LOT OF SYNTAX VARIATIONS
    
         

