use crate::params::KYBER_N;
use crate::reduce::{barrett_reduce, montgomery_reduce};

// Layer-order zetas in Montgomery domain, centered, regenerated for q=13835058055275898369
const ZETAS: [i128; 128] = [
    4611686018433653247i128,
    6775496934782943343i128,
    -2009471431703899311i128,
    -1328232688688911287i128,
    -1002745027200374681i128,
    4065724602514105411i128,
    2919437507106638680i128,
    319924368957496599i128,
    -4937142386123851074i128,
    -2046042962112950785i128,
    -5404690735978538842i128,
    -6606314814373324632i128,
    -270228248844215435i128,
    6129907493117356186i128,
    -4960492513664852441i128,
    -6059951808049000894i128,
    3669995908980165229i128,
    4471194529861214218i128,
    -1275871039369993539i128,
    4562826861878496655i128,
    2822996399665595795i128,
    5082037695556247343i128,
    745738841633068290i128,
    633169733644942350i128,
    3458111977077273059i128,
    4065489346010616149i128,
    6876880878865852470i128,
    -6806000428358751151i128,
    -3410546557051774221i128,
    -2069297829992143500i128,
    -5891018715525901177i128,
    262987071806669675i128,
    -4209832979942217088i128,
    -4853399977178133286i128,
    -4469635722433500072i128,
    -2719828446725532201i128,
    2932733688436728947i128,
    3225024695543939740i128,
    -437831722710114117i128,
    4689031949574032495i128,
    -460795627035938008i128,
    -2729900186852309429i128,
    4958831375230657507i128,
    4314914257997048595i128,
    2689539792066314476i128,
    1556876955611316366i128,
    4127901432139452371i128,
    4250483512101983420i128,
    -6256633931762637093i128,
    -4681664571588944144i128,
    156650692426433285i128,
    2069716819461342925i128,
    -3044589325454650383i128,
    1462662603041285163i128,
    4609624266595818327i128,
    6674403165336970061i128,
    -338581298071975759i128,
    2040836476977888315i128,
    -273191801007909499i128,
    -2656845851757036308i128,
    -44711985415143478i128,
    6353563406977357718i128,
    3031822331272221894i128,
    -762779014219402480i128,
    -2372743451200819209i128,
    -4479457842878286898i128,
    -5808516804873542315i128,
    5202493321066001563i128,
    2664425064816597460i128,
    4127525199519907716i128,
    -5367643274131333069i128,
    -2101288124888178948i128,
    -2164111735454328589i128,
    3426632667190719615i128,
    -1449132584730080406i128,
    -4033040700149638753i128,
    -4568336411430482635i128,
    5475667053731798313i128,
    4835718490655127805i128,
    -3262171357217770981i128,
    -721708503450034379i128,
    -442230070471120890i128,
    6488316196029542432i128,
    3668928761566150171i128,
    1879062554842413453i128,
    6622523374060929081i128,
    4497823662372655678i128,
    2181189622346755299i128,
    3343598498793886526i128,
    -5832667444522673062i128,
    -5769155328229301819i128,
    -4683268811401307848i128,
    -432338560991021804i128,
    -3488522677917641439i128,
    -1748976110565841208i128,
    1931908146623244118i128,
    101008600497379161i128,
    6678619682012113901i128,
    6864728106536110716i128,
    -4854416514682753834i128,
    2263811077158641856i128,
    -3831832212124189303i128,
    2577497029180678273i128,
    -3316505856631513396i128,
    141308948101872457i128,
    4037194506457022523i128,
    5142836145630396386i128,
    -1159634373834138383i128,
    1103814451303893121i128,
    -5107084311639924838i128,
    2580699593472304997i128,
    -4201594893426059755i128,
    4176366008162680626i128,
    2749976035880187188i128,
    -3221175483079064863i128,
    3864261972939933101i128,
    4915914795301596551i128,
    4691404023415064847i128,
    -2009294716216636780i128,
    -6666406931716436834i128,
    75700364447871879i128,
    -6382679092994900854i128,
    -1821567887061005068i128,
    6856719230399980910i128,
    1577653652171756991i128,
    393060495186118832i128,
    -701047631524101030i128,
    -313778452114125462i128,
];

// Final inverse scaling for this parameter set (Montgomery domain).
const INV_SCALE: i128 = 144115188075855872i128;

#[inline]
pub(crate) fn fqmul(a: i128, b: i128) -> i128 {
    let aa = barrett_reduce(a);
    let bb = barrett_reduce(b);
    montgomery_reduce((aa as u128).wrapping_mul(bb as u128))
}

#[inline]
pub(crate) fn zeta_at(i: usize) -> i128 {
    ZETAS[i]
}

#[inline]
pub fn ntt(r: &mut [i128]) {
    // In Kyber's layer ordering, zetas[0] (which equals MONT) is skipped; the
    // first stage starts with zetas[1].
    let mut k = 1usize;
    let mut len = KYBER_N / 2; // 128
    while len >= 2 {
        for start in (0..KYBER_N).step_by(2 * len) {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = barrett_reduce(r[j] - t);
                r[j] = barrett_reduce(r[j] + t);
            }
        }
        len >>= 1;
    }
}

pub fn invntt(r: &mut [i128]) {
    invntt_butterfly(r);
    for v in r.iter_mut() {
        *v = fqmul(*v, INV_SCALE);
    }
}

fn invntt_butterfly(r: &mut [i128]) {
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= KYBER_N / 2 {
        for start in (0..KYBER_N).step_by(2 * len) {
            let zeta = ZETAS[k];
            k -= 1;
            for j in start..start + len {
                let t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = barrett_reduce(r[j + len] - t);
                r[j + len] = fqmul(zeta, r[j + len]);
            }
        }
        len <<= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::KYBER_Q;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    const R: u128 = 1u128 << 64;

    fn to_mont(x: i128) -> i128 {
        let r_mod_q = R % KYBER_Q as u128;
        let r2 = r_mod_q.wrapping_mul(r_mod_q) % KYBER_Q as u128;
        let x_norm = ((x % KYBER_Q as i128) + KYBER_Q as i128) as u128 % KYBER_Q as u128;
        montgomery_reduce(x_norm.wrapping_mul(r2))
    }

    #[test]
    fn ntt_inv_roundtrip() {
        let mut rng = StdRng::seed_from_u64(123);
        for _ in 0..2 {
            let mut a = [0i128; KYBER_N];
            for v in a.iter_mut() {
                *v = rng.gen_range(0..KYBER_Q as i128);
            }
            let mut mont = [0i128; KYBER_N];
            for i in 0..KYBER_N {
                mont[i] = to_mont(a[i]);
            }
            ntt(&mut mont);
            invntt(&mut mont);
            for v in mont.iter_mut() {
                *v = montgomery_reduce(*v as u128);
            }
            for i in 0..KYBER_N {
                assert_eq!(barrett_reduce(a[i] - mont[i]), 0, "idx {}", i);
            }
        }
    }

    #[test]
    fn ntt_scale_probe() {
        // Verify that NTT + invntt roundtrip works correctly with the scaling factor
        assert_eq!(
            INV_SCALE,
            144115188075855872i128,
            "inv_scale mismatch in test"
        );
        let mut a = [0i128; KYBER_N];
        a[0] = 1;
        let mut mont = [0i128; KYBER_N];
        for i in 0..KYBER_N {
            mont[i] = to_mont(a[i]);
        }
        ntt(&mut mont);
        invntt(&mut mont);
        for v in mont.iter_mut() {
            *v = montgomery_reduce(*v as u128);
        }
        // Impulse should roundtrip to impulse in normal domain.
        for (i, v) in mont.iter().enumerate() {
            let expected = if i == 0 { 1 } else { 0 };
            assert_eq!(barrett_reduce(*v), expected, "idx {} val {}", i, v);
        }
    }
}
