hublot — Windows agent
======================

This mirrors THIS machine's desktop into the hublot panel running on another PC, and lets that
panel drive this machine's keyboard and mouse. Treat it accordingly: whoever holds the paired
panel can type here.

Nothing needs to be installed and no administrator rights are needed for the agent itself. One
step — the firewall rule — does need an administrator terminal, and it is the step everything
else depends on.


1. Put it somewhere it can stay
-------------------------------
   C:\Tools\hublot\win-agent.exe

   The logon task remembers this path, so moving the file later means re-running step 3.


2. Get its pairing details
--------------------------
   In a terminal, from that folder:

       .\win-agent.exe --pairing

   It prints a fingerprint and a token. You will paste both into the panel. The token authorises
   *enrolling* the panel once — it is not a password, and it stops working after the agent
   restarts with a panel already enrolled.

   Also note this machine's address:

       ipconfig | findstr IPv4


3. Start it at logon, and let the panel through the firewall
------------------------------------------------------------
   In an ADMINISTRATOR terminal:

       .\win-agent.exe --install --allow <the panel PC's address>

   That does two things: registers a logon task (so the agent starts when you sign in, with no
   console window), and adds an inbound firewall rule for UDP 7843 restricted to that one address.

   The rule matters more than it looks. QUIC is UDP, and Windows blocks inbound UDP by default —
   without the rule the agent listens happily and no connection ever arrives, which looks exactly
   like a broken agent. Scoping it to the panel's address rather than to a network profile is
   deliberate: Windows re-classifies networks as Private or Public on its own, and a rule that
   depends on that classification stops working for reasons unrelated to you.

   Check it took:

       .\win-agent.exe --status


4. Start it now, without signing out
------------------------------------
       schtasks /Run /TN "Hublot Agent"

   There is deliberately no window. If something goes wrong it is written to:

       %APPDATA%\hublot-agent\agent.log


5. Pair from the panel
----------------------
   Mirror tab → "+ pair" → address <this machine's IP>:7843, then the fingerprint and token from
   step 2. It should paint this desktop within a second or two.


Undoing it
----------
       .\win-agent.exe --uninstall        (removes the logon task and the firewall rule)

   Delete %APPDATA%\hublot-agent to forget the identity as well, which un-pairs every panel.


Notes
-----
* Clipboard is synced automatically, in both directions, between Windows machines. Anything you
  copy here reaches the panel's machine within about half a second. There is no off switch; see
  THREAT-MODEL.md R10 if that matters to you.
* The agent captures display 0 only. Multi-monitor is not handled yet.
* It runs in your user session, not as a service, because a service has no desktop to capture.
