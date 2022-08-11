from params import KYBER_N
from util import conditional_subq

def poly_conditional_subq(r):
    """
    subtract KYBER_Q from each coefficient from polynomial r
    :param r:
    :return:
    """
    for i in range(0, KYBER_N):
        r[i] = conditional_subq(r[i])
    return r

def compress_poly(poly_a):
    t = [ 0 for x in range(0,8)]


    pass
"""
    /**
     * Performs lossy compression and serialization of a polynomial
     *
     * @param polyA
     * @param paramsK
     * @return
     */
    public static byte[] compressPoly(short[] polyA, int paramsK) {
        byte[] t = new byte[8];
        polyA = Poly.polyConditionalSubQ(polyA);
        int rr = 0;
        byte[] r;
        switch (paramsK) {
            case 2:
            case 3:
                r = new byte[KyberParams.paramsPolyCompressedBytesK768];
                for (int i = 0; i < KyberParams.paramsN / 8; i++) {
                    for (int j = 0; j < 8; j++) {
                        t[j] = (byte) (((((polyA[8 * i + j]) << 4) + (KyberParams.paramsQ / 2)) / (KyberParams.paramsQ)) & 15);
                    }
                    r[rr + 0] = (byte) (t[0] | (t[1] << 4));
                    r[rr + 1] = (byte) (t[2] | (t[3] << 4));
                    r[rr + 2] = (byte) (t[4] | (t[5] << 4));
                    r[rr + 3] = (byte) (t[6] | (t[7] << 4));
                    rr = rr + 4;
                }
                break;
            default:
                r = new byte[KyberParams.paramsPolyCompressedBytesK1024];
                for (int i = 0; i < KyberParams.paramsN / 8; i++) {
                    for (int j = 0; j < 8; j++) {
                        t[j] = (byte) (((((polyA[8 * i + j]) << 5) + (KyberParams.paramsQ / 2)) / (KyberParams.paramsQ)) & 31);
                    }
                    r[rr + 0] = (byte) ((t[0] >> 0) | (t[1] << 5));
                    r[rr + 1] = (byte) ((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
                    r[rr + 2] = (byte) ((t[3] >> 1) | (t[4] << 4));
                    r[rr + 3] = (byte) ((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
                    r[rr + 4] = (byte) ((t[6] >> 2) | (t[7] << 3));
                    rr = rr + 5;
                }
        }

        return r;
    }
"""