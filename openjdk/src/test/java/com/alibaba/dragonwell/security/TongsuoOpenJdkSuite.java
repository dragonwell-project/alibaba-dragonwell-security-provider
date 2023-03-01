package com.alibaba.dragonwell.security;

import org.conscrypt.*;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
    DragonwellSecurityProviderEndToEndTest.class,
})

public class TongsuoOpenJdkSuite {

}
