// Practice messages. All names, addresses and links are made up for training.
globalThis.PHISHPROOF_SAMPLES = [
  {
    phish: true,
    text: `From: PayPal Security <service@paypa1-security.com>
Subject: Your account has been limited

Dear Customer,

We noticed unusual sign-in activity on your account. Your account will be suspended within 24 hours unless you verify your account.

<a href="http://paypa1-security.com/login">https://www.paypal.com/verify</a>

PayPal Security Team`,
    why: 'The sender is "paypa1" with a number 1, the link text shows paypal.com but goes somewhere else, and it pressures you with a 24-hour deadline.',
  },
  {
    phish: false,
    text: `From: Ms. Rivera <jrivera@lincolnhs.org>
Subject: Chemistry lab moved to Thursday

Hi everyone,

Our lab is moving from Wednesday to Thursday this week because of the assembly. Bring your goggles and the worksheet from Monday.

The updated schedule is on the class page: https://lincolnhs.org/chem/schedule

Thanks,
Ms. Rivera`,
    why: 'It comes from the school\'s own domain, links to that same domain, asks for nothing personal and gives you no deadline pressure.',
  },
  {
    phish: true,
    text: `From: USPS <tracking.update@gmail.com>
Subject: Package on hold - unpaid fee

Your package could not be delivered due to an unpaid fee of $1.99. Pay now to avoid return: https://bit.ly/usps-redeliver

FINAL NOTICE. ACT NOW.`,
    why: 'USPS doesn\'t email from Gmail, the shortened link hides where it goes, and "unpaid fee" plus ALL-CAPS pressure is a classic delivery scam.',
  },
  {
    phish: true,
    text: `From: Principal Adams <principal.adams.office@outlook.com>
Subject: Quick favor

Hi, I'm in a meeting and can't talk. I need you to buy 4 Apple gift cards for a staff surprise. Send me the codes immediately and I'll pay you back.`,
    why: 'A "principal" writing from a free Outlook account and asking for gift card codes urgently is a gift-card scam. Check with the real person another way.',
  },
  {
    phish: false,
    text: `From: GitHub <noreply@github.com>
Subject: [GitHub] A new SSH key was added to your account

Hey there,

A new public key was added to your account. If you added this key, you can ignore this email.

If you didn't, review your keys at https://github.com/settings/keys`,
    why: 'It comes from github.com, the link goes to github.com, and it doesn\'t ask you to type a password into the email or rush you.',
  },
  {
    phish: true,
    text: `From: Microsoft Account Team <alerts@rnicrosoft-support.co>
Reply-To: helpdesk7731@protonmail.com
Subject: Password expires today

Your Office password expires today. Keep your current password by confirming your login here:
http://45.133.9.12/office365/keep-password

Attachment: Password_Policy.pdf.exe`,
    why: '"rnicrosoft" uses r+n to look like an m, replies go to a different address, the link is a bare IP address, and the attachment is really an .exe program.',
  },
];
