# KyberPAKE-Mobile

#### Installation
Step 1. Add it in your root build.gradle at the end of repositories:
```java
allprojects {
		repositories {
			...
			maven { url 'https://jitpack.io' }
		}
	}
 ```
 
Step 2. Add the dependency
```java
dependencies {
	  implementation 'com.github.afDursun:PQC-Library-AndroidJava:Tag'
	}
 ```
 

#### Example
```java
/* Pake C0 */
PakeC0 c0 = KyberPake.pake_c0( cid, sid, pw);

/* Pake S0 */
PakeS0 s0 = KyberPake.pake_s0( c0.getSend(), c0.getGamma(), sid );

/* Pake C1 */
PakeC1 c1 = KyberPake.pake_c1( s0.getSend(), c0.getSk(), c0.getState_1() );

/* Pake S1 */
byte[] sharedeSecretKey_s1 =  KyberPake.pake_s1( c1.getK_3_c(), s0.getState());

/* Output SessionKey */
Log.d("KyberPAKE-C1.SessionKey", hex( c1.getSharedSecretKey() ));
Log.d("KyberPAKE-S1.SessionKey", hex( sharedeSecretKey_s1 ));
 ```
 
## Acknowledgment
- This research was partially supported by TUBITAK under Grant No. 121R006
