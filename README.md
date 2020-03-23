# Shoulder Surfing Protector

## Description

Shoulder Surfing Protector is capable of protect your password by changing it every single minute, so a Social Engineering Hacker will not be able to stole your password or take control of your machine. All you need is a Secret Key and a format pattern based on datetime.

Is not recommended to use in root accounts because, eventually, it will be the only way to recover your account if you forget your Secret Key or something goes wrong.

## Install

1. Login with root access

2. Move the binary(in "build" folder) to your bin(or sbin) folder(ex: "/usr/local/sbin")
```bash
echo $PATH
cp build/ssp /usr/local/sbin
```

3. Now u'r ready to go. If you need a help:
```bash
ssp -h
```

## How to Use

1. First, you need to create a Secret Key and choose a format pattern
```bash
ssp -config
```

2. Follow the instructions.
```bash
Username: USER
Date format(yyyymmddhhii): yyyymmddhhii
Secret key: **********
```
Username: The account with a password based on an algorithm.

Date format: It is a format pattern to generate the password(based on your secret key).
```bash
yyyy: Year
  mm: Month
  dd: Day
  hh: Hour
  ii: Minute
```
Secret key: Only you will know this. This will be the base for your algorithm

The complicated part in here is understand de "Date format" pattern, because you need to know exactly how it works. Your secret key is formed with characters that we can assign to an [ASCII table](https://ascii.cl/) and iterate over this table according to numbers in your date format pattern(don't worry, examples below).

Examples:
```bash
Username: foo
Date format(yyyymmddhhii): mmddyyyyhhii
Secret key: password1234
```

In the example, the date format pattern is "month-day-year-hour-minutes". The algorithm is very simple, just iterate over your secret key adding a number based on your pattern. So, if today is Jan 03, 2020 at 14:07 hrs...

```
password1234
010320201407
(p+0)+(a+1)+(s+0)+(s+3)+(w+2)+(o+0)+(r+2)+(d+0)+(1+1)+(2+4)+(3+0)+(4+7)
  p  +  b  +  s  +  v  +  y  +  o  +  t  +  d  +  2  +  6  +  3  +  ;
```

The password will be: **pbsvyotd263;**

And in the next minute will be: **pbsvyotd263<**

In case that your secret was password123 instead of password1234, the last pattern will not be executed, so your password will change every 10 minutes.

The password will be: **pbsvyotd263**

And in the next minute will be(exactly the same): **pbsvyotd263**

But, at 14:10, it will be: **pbsvyotd264**
