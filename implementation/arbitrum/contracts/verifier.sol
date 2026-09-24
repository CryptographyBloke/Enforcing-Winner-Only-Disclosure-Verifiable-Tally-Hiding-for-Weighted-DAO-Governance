// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 11295298323947709001626674101022738789069747900721879780852145294015795317401;
    uint256 constant alphay  = 7910122642305692522944506894992234831700642746985302918787551708797367472700;
    uint256 constant betax1  = 4622594993404954224759110630280277315124660973071615359285096273142384865178;
    uint256 constant betax2  = 15072821494349329829847302202980063920141889554518527019717397790922516423446;
    uint256 constant betay1  = 18298045628429073797991437735568437049139916460477067988678168822140450924524;
    uint256 constant betay2  = 16392367599856245997989444351478958212072126698052830153956267760670895332969;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 14055644566138088029558233109688229313493972509127352683602058854590630390615;
    uint256 constant deltax2 = 21455811986812279722226346199579085654737305622583487604091569119622615528595;
    uint256 constant deltay1 = 6555629977280705248639227467554465829885560021863954892125627931961126816727;
    uint256 constant deltay2 = 20714323108984353870705761590067831157774723682722411801255957036208141624290;


    uint256 constant IC0x = 15861585753187624243646369059468629703528105999767038062076357356989468437389;
    uint256 constant IC0y = 4937671642480562458644060772398661400686042008421055299289767267990941974976;

    uint256 constant IC1x = 10580644475174525072245998216646346266850260373844966172467459024697145891450;
    uint256 constant IC1y = 1515148869066856261329817156427562506219706688323365616933228901331529783365;

    uint256 constant IC2x = 20806986251712714584300865487245456067653667747185045377185957731044447593492;
    uint256 constant IC2y = 20993120652325724949110683326481509382301996661227650067414116992587418705127;

    uint256 constant IC3x = 21567408315853079565961641678925942291955463050139109966824692055471542036137;
    uint256 constant IC3y = 3360387439861243918420039271630587015382730287421973695950728188818450921509;

    uint256 constant IC4x = 18034423275245026854194203871466643445492297905302422705983314583206953753106;
    uint256 constant IC4y = 21590846404771218660262993202675737331231391680254549304574025921539213664773;

    uint256 constant IC5x = 4333859143218890959459231941945445760872952177397808042475346765777488621789;
    uint256 constant IC5y = 4232317123271826549494262132442853733044092713830999166784945857070947392679;

    uint256 constant IC6x = 318958651933041981889092922210872105478329439679405633805091778897425181094;
    uint256 constant IC6y = 11046397181286568771784187515085391156979876338236546002734754461970235655954;

    uint256 constant IC7x = 17261682329643729573910610676252514912594535208091316865136025226319195933356;
    uint256 constant IC7y = 19225616959166788199096292035038676063695228814196690831302973119800972583036;

    uint256 constant IC8x = 12978669230414695985219124597989421744972889261216922580058097539922212214761;
    uint256 constant IC8y = 17344383362863521162161732361298586076861840240011953197411090736811012498453;

    uint256 constant IC9x = 9749237594691231990008295496633182596435437019029729594760935329469892379518;
    uint256 constant IC9y = 14604541399165662844049307376070614904112698535695280235738102895675485667729;

    uint256 constant IC10x = 1954926266346067952107915946411223368333027489670081059410685079436701464232;
    uint256 constant IC10y = 20726832983479764512586009404429354306836062309918944838506385113186900076338;

    uint256 constant IC11x = 9732314744234254814372337579342484571713720752612974195989795083592845544444;
    uint256 constant IC11y = 2423975908459600756382650124290644385428733291653464786137764643940916873967;

    uint256 constant IC12x = 1683887909057914277019630203828327465405301146428077381058291633967721353546;
    uint256 constant IC12y = 17571455022637408164265202574635222623354247148178205256938883812289482869665;

    uint256 constant IC13x = 8137292021664316873740573190826557785678582811917388178313504752876180200921;
    uint256 constant IC13y = 16288319607708583786349084070000980077618385201895371403130352942421826137975;

    uint256 constant IC14x = 5115039012374412575854500291550154727354876758678398454142950384115625178950;
    uint256 constant IC14y = 1753481104552505550144978824210429778604531378771140753168313764278922375012;

    uint256 constant IC15x = 14885242607894855769671019533909646459703058668241418734032310131202500959517;
    uint256 constant IC15y = 1656785676203128531729344755468790391409279988147452028978966740600509727082;

    uint256 constant IC16x = 7864998869065678342239407944017719340424607665222214866508825086696824140234;
    uint256 constant IC16y = 3842053038094883068145282855158580770149049401919803081515256072899626902866;

    uint256 constant IC17x = 19212079652776697698847040236647807748105297661623632735979930961227882044885;
    uint256 constant IC17y = 16355573492559772488033999738929416876617415567108387813254412527126961680600;

    uint256 constant IC18x = 11748561743750228582505060394467929195942628331642124991925018421621057055507;
    uint256 constant IC18y = 10114884241702932424874919346925554771338927846128902203466789973904048885056;

    uint256 constant IC19x = 7914241482223984933705931315073847841113039509526728721604928284530216474788;
    uint256 constant IC19y = 3904423816285112295362205231565824935846447215127120456716281879792401055777;

    uint256 constant IC20x = 20523949047100643935182622393088662851523837369366450026804678449248672403953;
    uint256 constant IC20y = 7841091433138824724453857195793937806533133164188917863400803301428861835954;

    uint256 constant IC21x = 2725877598418218328812796487857980034735336052667452364010020867481595221616;
    uint256 constant IC21y = 16326280532802876496327751725348257823949156186065583298203430492884806755531;

    uint256 constant IC22x = 7036973566475770217285755235206900409120237936447444135908503287903891273201;
    uint256 constant IC22y = 4830960051275955613764094516486227630701277827096374341102677015139846383702;

    uint256 constant IC23x = 14402010210865307274299130543698350308507914026586019308180341516771103377994;
    uint256 constant IC23y = 11896512008265321124947249655568963127895910064607962764640327351691063010317;

    uint256 constant IC24x = 21730422393293465164205763572770538251602942057582924209731553496529656154891;
    uint256 constant IC24y = 243569462951769519899870983769652340124918966967003544954696139787587876264;

    uint256 constant IC25x = 4851669144759426496443687275691350932686917043192308735508124633270842157104;
    uint256 constant IC25y = 17298928330931730211993211047489920680731369059126089759231261154655209649105;

    uint256 constant IC26x = 14488690693542477218034919724931737986379206282116636628106600245756502325267;
    uint256 constant IC26y = 13644471027152446717269562246960712033255406940715720141258494188230181120046;

    uint256 constant IC27x = 16849110232917621570123469109438484622248762723249009987365297268500522952825;
    uint256 constant IC27y = 9485602522202133180582314886065210008814292877499440554997926381798100368438;

    uint256 constant IC28x = 11067050379090597291818391096939456427189558505715262143331044616603714967623;
    uint256 constant IC28y = 2668367485522928341435566229304072919802704607957210004703691359456135225912;

    uint256 constant IC29x = 20676716802714257920975753113218260684898859516342571654364386323862785053714;
    uint256 constant IC29y = 9713138719892544899958164350561348286460764611910026859182502595292955268951;

    uint256 constant IC30x = 7301817324184297463339339488453072448329058372325191431898388861443438745942;
    uint256 constant IC30y = 17007813367573665966976744287623499583804692106113328620028638881640729841978;

    uint256 constant IC31x = 9767970988584666759931149646944180631348994244596910286897367715712065552074;
    uint256 constant IC31y = 13832443737750503959494356623563223561396703984725938566758976255089233108805;

    uint256 constant IC32x = 3865311242380269674465258087825489421504955051989344717667392918333741940360;
    uint256 constant IC32y = 4778932165698536705554091871334786045353929730931792296766242768212025578241;

    uint256 constant IC33x = 19072168188581468901703830760395766465820479872531194054407564598390750970252;
    uint256 constant IC33y = 4497485977811885161261028289342824597979665602401445852259269322845553092862;

    uint256 constant IC34x = 428975386591148356272073598620918211295966748525843946054795544606408831838;
    uint256 constant IC34y = 12893408731320040302683315901380122245955038967166155994721096468354946683969;

    uint256 constant IC35x = 9207981061414764069033236277725860364912139772233186668338751355003692473456;
    uint256 constant IC35y = 19749505591136500764861815465833408334296124484624743598771859968514984575416;

    uint256 constant IC36x = 18006769592581057930046679905586610633290537492329962479272123937403772659885;
    uint256 constant IC36y = 4102559201232501347981346014554399457911457395075230632796499941279420361184;

    uint256 constant IC37x = 4302330102897737613366531379781486864081569257362245398095945886689156389620;
    uint256 constant IC37y = 21052620964174554484160376613825139104314884913137521037946270481214112048603;


    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[37] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x

                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))

                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))

                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))

                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))

                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))

                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))

                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))

                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))

                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))

                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))

                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))

                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))

                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))

                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))

                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))

                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))

                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))

                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))

                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))

                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))

                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))

                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))

                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))

                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))

                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))

                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))

                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))

                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))

                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))

                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))

                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))

                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))

                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))

                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))

                g1_mulAccC(_pVk, IC35x, IC35y, calldataload(add(pubSignals, 1088)))

                g1_mulAccC(_pVk, IC36x, IC36y, calldataload(add(pubSignals, 1120)))

                g1_mulAccC(_pVk, IC37x, IC37y, calldataload(add(pubSignals, 1152)))


                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F

            checkField(calldataload(add(_pubSignals, 0)))

            checkField(calldataload(add(_pubSignals, 32)))

            checkField(calldataload(add(_pubSignals, 64)))

            checkField(calldataload(add(_pubSignals, 96)))

            checkField(calldataload(add(_pubSignals, 128)))

            checkField(calldataload(add(_pubSignals, 160)))

            checkField(calldataload(add(_pubSignals, 192)))

            checkField(calldataload(add(_pubSignals, 224)))

            checkField(calldataload(add(_pubSignals, 256)))

            checkField(calldataload(add(_pubSignals, 288)))

            checkField(calldataload(add(_pubSignals, 320)))

            checkField(calldataload(add(_pubSignals, 352)))

            checkField(calldataload(add(_pubSignals, 384)))

            checkField(calldataload(add(_pubSignals, 416)))

            checkField(calldataload(add(_pubSignals, 448)))

            checkField(calldataload(add(_pubSignals, 480)))

            checkField(calldataload(add(_pubSignals, 512)))

            checkField(calldataload(add(_pubSignals, 544)))

            checkField(calldataload(add(_pubSignals, 576)))

            checkField(calldataload(add(_pubSignals, 608)))

            checkField(calldataload(add(_pubSignals, 640)))

            checkField(calldataload(add(_pubSignals, 672)))

            checkField(calldataload(add(_pubSignals, 704)))

            checkField(calldataload(add(_pubSignals, 736)))

            checkField(calldataload(add(_pubSignals, 768)))

            checkField(calldataload(add(_pubSignals, 800)))

            checkField(calldataload(add(_pubSignals, 832)))

            checkField(calldataload(add(_pubSignals, 864)))

            checkField(calldataload(add(_pubSignals, 896)))

            checkField(calldataload(add(_pubSignals, 928)))

            checkField(calldataload(add(_pubSignals, 960)))

            checkField(calldataload(add(_pubSignals, 992)))

            checkField(calldataload(add(_pubSignals, 1024)))

            checkField(calldataload(add(_pubSignals, 1056)))

            checkField(calldataload(add(_pubSignals, 1088)))

            checkField(calldataload(add(_pubSignals, 1120)))

            checkField(calldataload(add(_pubSignals, 1152)))


            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
