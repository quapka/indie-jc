package applet;

import applet.jcmathlib.OperationSupport;

public class CardType {
    // NOTE The CARD_TYPE value is dynamically overriden duing the build process
    //      thus allowing to build either SIMULATOR or JCOP4_P71 versions of the applet
    public final static short CARD_TYPE = OperationSupport.SIMULATOR;
}
