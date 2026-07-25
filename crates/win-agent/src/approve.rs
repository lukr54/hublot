//! Asking the person sitting at this machine.
//!
//! This is the whole of the pairing experience on the machine being shared: a dialog, six digits,
//! Yes or No. Nothing is typed and nothing is transcribed.
//!
//! The wording matters more than the code does. Whoever reads this box is being asked to hand over
//! their keyboard and mouse to another computer, so it says that plainly, says where the request
//! came from, and defaults to No.

use windows::core::HSTRING;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_SETFOREGROUND, MB_SYSTEMMODAL, MB_YESNO,
};

pub struct Desktop;

impl agent_core::Approver for Desktop {
    fn ask(&self, peer: &str, sas: &str) -> bool {
        // Strip the port: the address is the useful half, and "192.168.1.20:52431" invites the
        // reader to compare a number that changes every connection.
        let from = peer.rsplit_once(':').map(|(h, _)| h).unwrap_or(peer);
        let text = format!(
            "A hublot panel at {from} wants to control this PC.\n\n\
             It will be able to see this screen and use this keyboard and mouse.\n\n\
             Confirmation code:   {sas}\n\n\
             Allow it only if the panel is showing the same six digits.\n\
             If it is showing something else, someone is between you and it."
        );
        let answer = unsafe {
            MessageBoxW(
                Some(HWND::default()),
                &HSTRING::from(text),
                &HSTRING::from("hublot — allow this machine to be controlled?"),
                // System modal and foreground because the agent has no window of its own, so
                // without these the box can open behind whatever is on screen and the panel simply
                // appears to hang. Default is No: this dialog should never be dismissable by
                // reflex.
                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SYSTEMMODAL | MB_SETFOREGROUND,
            )
        };
        answer == IDYES
    }
}
