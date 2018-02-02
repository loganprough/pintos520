Logan Prough

Files changed:

  src/tests/threads/alarm-wait.c
    added test_alarm_mega function
    void
    test_alarm_mega (void)
    {
      test_sleep (5, 70);
    }

  src/tests/threads/tests.c
    added alarm-mega test
    {"alarm-mega", test_alarm_mega},

  src/tests/threads/Rubric.alarm
    added alarm-mega test above alarm-multiple test
    4 alarm-mega

  src/tests/threads/Make.tests
    added alarm-mega test
    alarm-mega alarm-multiple alarm-simultaneous...

  src/tests/threads/tests.h
    added definition for test_alarm_mega
    extern test_func test_alarm_mega;

  src/tests/threads/alarm-mega.ck
    created alarm-mega .ck file
    # -*- perl -*-
    use tests::tests;
    use tests::threads::alarm;
    check_alarm (70);

