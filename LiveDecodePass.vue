<template>
  <div class="codereader">
    <div class="switchcam" @click="changeVideoDevice" v-if="hasCamera && videoInputDevices.length > 1">
      <IconeCam />
    </div>
    <div v-if='hasCamera' class="codereader--video">
        <div v-if="cameraDisabled" class="codereader--video--text">{{$CD('CAMERA_DISABLED_ERROR')}}</div>
      <video id="video" ></video>
    </div>
    <p>{{$CD('OK_SCAN_PASS_EXPLAIN')}}</p>
    <ProgressBar v-if="displayProgressBar"/>
    <!-- <img :src="imgDebug" v-if="imgDebug"> -->
    <span class="sep">{{ $CD('SEPARATOR_OR') }}</span>
    <label class="uploadcustom btn"  for="upload-photo">{{$CD('OK_BUTTON_DOWNLOAD')}}</label>
    <input id="upload-photo" type="file" accept=".jpg,.jpeg,.png,application/pdf" name="upload document" @change="filechange($event)">
    <span class="info-format">{{$CD('OK_ACCEPTED_FILES')}}</span>
    <div class="modals" v-if="loaded">
      <modal name="error-non-valide" :width="300" :height="300" :adaptive="true">
          <div class="modal--inner">
            <div class="modal--icone">
              <IconeWarningMin />
            </div>
            <p>{{$CD('OK_MODAL_ERROR_INVALID')}}</p>
            <button type="button" class="btn" @click="$modal.hide('error-non-valide')">{{$CD('OK_MODAL_ERROR_INVALID_BUTTON')}}</button>
          </div>
      </modal>
      <modal name="error-non-decode" :width="300" :height="300" :adaptive="true">
          <div class="modal--inner">
            <div class="modal--icone">
              <IconeWarningMin />
            </div>
            <p>{{$CD('OK_MODAL_ERROR_NO_DECODE')}}</p>
            <button type="button" class="btn" @click="$modal.hide('error-non-decode')">{{$CD('OK_MODAL_ERROR_NO_DECODE_BUTTON')}}</button>
          </div>
      </modal>
      <modal name="error-not-found" :width="300" :height="300" :adaptive="true">
          <div class="modal--inner">
            <div class="modal--icone">
              <IconeWarningMin />
            </div>
            <p>{{$CD('OK_MODAL_ERROR_NO_DECODE')}}</p>
            <button type="button" class="btn" @click="$modal.hide('error-not-found')">{{$CD('OK_MODAL_ERROR_NO_DECODE_BUTTON')}}</button>
          </div>
      </modal>
    </div>
  </div>
</template>

<script>
import {BrowserMultiFormatReader, BarcodeFormat, DecodeHintType} from '@zxing/library';
import base32Decode from 'base32-decode'
import b45 from "base45-js";
import b64 from 'base64-js';
import sha256 from 'js-sha256';
import pako from "pako";
import { verify, webcrypto, cbor } from 'cosette/build/sign.js';
import { fromByteArray as encodeb64, toByteArray as decodeb64 } from 'base64-js';

let DCCCerts;
let DCCBlacklist;

const pdfjsLib = window['pdfjs-dist/build/pdf'];
// The workerSrc property shall be specified.
pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://mozilla.github.io/pdf.js/build/pdf.worker.js';

const hints = new Map()
hints.set(DecodeHintType.POSSIBLE_FORMATS, [BarcodeFormat.QR_CODE, BarcodeFormat.DATA_MATRIX])
hints.set(DecodeHintType.TRY_HARDER, true)
const codeReader = new BrowserMultiFormatReader(hints);

let interval;

const cropCanvas = (sourceCanvas,left,top,width,height) => {
    let destCanvas = document.createElement('canvas');
    destCanvas.width = width;
    destCanvas.height = height;
    destCanvas.getContext("2d").drawImage(
        sourceCanvas,
        left,top,width,height,  // source rect with content to crop
        0,0,width,height);      // newCanvas, same size as source rect
    return destCanvas;
}
let barcodeDetector;
try {
barcodeDetector = new BarcodeDetector({
  // (Optional) A series of barcode formats to search for.
  // Not all formats may be supported on all platforms
  formats: [
    //'aztec',
    'qr_code',
  ]
});
}catch(err) {
  console.log("BarcodeDetector is not supported", err);
}

export default {
  data: function() {
    return {
      loaded: false,
      selectedDeviceId: undefined,
      videoInputDevices: [],
      imgDebug: undefined,
      displayProgressBar: false,
      hasCamera: true,
      cameraDisabled: false,
    }
  },
  async mounted() {
    this.loaded = true;
    let {data} = await this.$axios.get(window.location.origin+'/api/getcertificates');
    DCCCerts = data.DCCCerts;
    DCCBlacklist = data.DCCBlacklist;
    await this.listVideoDevices();
    this.loaded = true;

    if(!this.hasCamera) return;

    this.start();
    console.log('ZXing code reader initialized')
    interval = setInterval(()=>{
      this.listVideoDevices();
    }, 1000);
  },
  methods: {
    async  parseCert(cert) {
      // Certs are doube-base64 encoded
      const raw = b64.toByteArray(cert);
      const pem = new TextDecoder().decode(raw);
      try {
        return await this.exportCertificate(pem);
      } catch (err) {
        // The server returns both certificates and raw public keys
        return await exportPublicAsCert(pem);
      }
    },
    async exportCertificate(pem) {
      const x509cert = new X509Certificate(pem);

      // Export the certificate data.
      return {
        serialNumber: x509cert.serialNumber,
        subject: x509cert.subject,
        issuer: x509cert.issuer,
        notBefore: x509cert.notBefore.toISOString(),
        notAfter: x509cert.notAfter.toISOString(),
        signatureAlgorithm: x509cert.signatureAlgorithm.name,
        fingerprint: Buffer.from(await x509cert.getThumbprint(crypto)).toString('hex'),
        ...(await exportPublicKeyInfo(x509cert.publicKey))
      };
    },
    async listVideoDevices(){
      let videoInputDevices =  await codeReader.listVideoInputDevices();
      this.videoInputDevices = videoInputDevices;
      if(!videoInputDevices || !videoInputDevices[0]) {
        this.hasCamera = false
      } else {
        let vdbackIndex = videoInputDevices.findIndex((vd)=>{
          return (vd.label.indexOf('ack') > -1 || vd.label.indexOf('arr') > -1)
        });
        if(vdbackIndex >= 0) {
          this.selectedDeviceId = videoInputDevices[vdbackIndex].deviceId;
          this.selectedDeviceIndex = vdbackIndex;
        }else {
          this.selectedDeviceId = videoInputDevices[0].deviceId;
          this.selectedDeviceIndex = 0;
        }
        clearInterval(interval);
      }
    },
    async pdfToJpeg(pdfData) {
      var loadingTask = pdfjsLib.getDocument({
          data: pdfData
      });

      let pdf = await loadingTask.promise;
      let page = await pdf.getPage(2);
      let x = 10;
      let viewport = page.getViewport({
          scale: x
      });

      const canvas = document.createElement('canvas');
      const context = canvas.getContext('2d');
      canvas.height = viewport.height;
      canvas.width = viewport.width;

      const renderContext = {
        canvasContext: context,
        viewport: viewport
      };
      const renderTask = page.render(renderContext);
      await renderTask.promise;

      // let newcanva = cropCanvas(canvas, 200, 100, 200, 200)
      // let jpeg = await newcanva.toDataURL("image/jpeg");

      let newcanva = cropCanvas(canvas, 620/2*x, 30/2*x, 500/2*x, 500/2*x)
      let jpeg = await newcanva.toDataURL("image/jpeg");
      //let jpeg = await canvas.toDataURL("image/jpeg");

      return {canvas: canvas,jpeg: jpeg};
    },
    readFileBinary(file) {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = res => {
          resolve(res.target.result);
        };
        reader.onerror = err => reject(err);
        reader.readAsArrayBuffer(file);
      });
    },
    async filechange (event) {

      const input = event.target;
      if (input.files && input.files[0]) {
        this.displayProgressBar = true;
        var reader = new FileReader();
        reader.onloadend = async (e) => {
          try {
            if(e.target.result.indexOf("data:application/pdf") == 0) {
              let b64data = e.target.result.replace('data:application/pdf;base64,', '');
              let pdfBinaryData  = atob(b64data)
              let jpegb64 = await this.pdfToJpeg(pdfBinaryData);
              let result;
              if(barcodeDetector) {
                try {
                  const barcodes = await barcodeDetector.detect(jpegb64.canvas);
                  if(barcodes && barcodes.length > 0) {
                    result = {text: barcodes[0].rawValue};
                  }
                } catch (e) {
                  console.error('Barcode detection failed:', e);
                }
              } else {
                result = await codeReader.decodeFromImageUrl(jpegb64.jpeg)
              }

              this.analyseResult(result);
            } else {
              let result;
              if(barcodeDetector) {
                let bitmap = await createImageBitmap(event.target.files[0]);
                const barcodes = await barcodeDetector.detect(bitmap);
                if(barcodes && barcodes.length > 0) {
                  result = {text: barcodes[0].rawValue};
                }
                if(!result) {
                  throw new Error('No qrcode detected');
                }
              } else {
                result = await codeReader.decodeFromImageUrl(e.target.result)
              }
              this.analyseResult(result);
            }
            this.displayProgressBar = false;
          } catch(err) {
            this.$modal.show('error-not-found')
            this.displayProgressBar = false;
            this.retry();
          }
        };
        reader.readAsDataURL(input.files[0]);
      }
    },
    async changeVideoDevice() {
      codeReader.reset();
      this.selectedDeviceIndex++;
      if(this.selectedDeviceIndex == this.videoInputDevices.length){
        this.selectedDeviceIndex = 0;
      }
      this.selectedDeviceId = this.videoInputDevices[this.selectedDeviceIndex].deviceId;
      this.start();
    },
    retry() {
      codeReader.reset();
      this.start();
      this.displayProgressBar = false;
    },
    async analyseResult(result) {
      if(result.text.indexOf("#HC1:") > -1) {
        result.text = "HC1:"+decodeURI(result.text.split('#HC1:')[1])
      }
      if(result.text.startsWith("HC1:") || result.text.startsWith("EX1:")) {
        try {
          let data = await this.decode(result.text);
          this.$emit('done', result.text, data);
          codeReader.stopContinuousDecode()
        } catch (err) {
          console.log(err);
          this.$modal.hide('error-non-decode');
          this.retry();
        }
      } else if (result.text.startsWith("DC")) {
        try {
          let data = await this.decode2D(result.text);
          this.$emit('done', result.text, data);
          codeReader.stopContinuousDecode();
        } catch (err) {
          console.log(err);
          this.$modal.hide('error-non-decode');
          this.retry();
        }
      } else {
        this.$modal.hide('error-non-valide');
        this.retry();
      }
    },
    async start() {
      console.log(`Started decode from camera with id ${this.selectedDeviceId}`)
      try {
        await codeReader.decodeFromVideoDevice(this.selectedDeviceId, 'video', async (result)=> {
          if(result == null) {
            return;
          }
          this.displayProgressBar = true;
          this.analyseResult(result);
        });
      }catch(err) {
        if(err.message == "Permission denied") {
          this.cameraDisabled = true;
        }
      }
    },
    async getCertificatePublicKey({publicKeyAlgorithm, publicKeyPem}) {
      const der = decodeb64(publicKeyPem);
      const public_key = await webcrypto.subtle.importKey('spki', der, publicKeyAlgorithm, true, [
        'verify'
      ]);
      return public_key;
    },
    findDGCPublicKey(kid) {
        if (!DCCCerts[kid]) throw new Error("UnknownKid: "+kid);
        const certificate = DCCCerts[kid];
        const notAfter = new Date(certificate.notAfter);
        const notBefore = new Date(certificate.notBefore);
        // Verify that the certificate is still valid.
        const now = new Date();
        if (now > notAfter || now < notBefore) throw new Error('Invalid certificate');
        return certificate;
    },
    checkBlacklist(hash) {
      return (DCCBlacklist.indexOf(hash) > -1);
    },
    async decode(qrCode) {
      qrCode = qrCode.replace("HC1:", '');
      qrCode = qrCode.replace("EX1:", ''); // pass exemption
      let coseData = b45.decode(qrCode);
      coseData = pako.inflate(coseData);
      let kid;
      let certificate;
      const rawData = await verify(coseData, async (kid_bytes)=>{
        kid = encodeb64(kid_bytes);
        certificate = await this.findDGCPublicKey(kid);
        const key = await this.getCertificatePublicKey(certificate);
		    return { key };
      });
      const cborData = await cbor.decodeFirst(coseData);
      let [headers1, headers2, cbor_data, signature] = cborData.value;
      const cborData2 = await cbor.decodeFirst(cbor_data);
      const hcert = cborData2.get(-260)?.get(1) || {};

      let cert = this.certificateInfo(hcert);

      if(this.checkBlacklist(cert.hash)) {
        throw new Error("Pass frauduleux");
      }
      return cert;
    },
    certificateInfo(hcert) {
      const common = {
        first_name: hcert.nam.gn || (hcert.nam.gnt || '-').replace(/</g, ' '),
        last_name: hcert.nam.fn || hcert.nam.fnt.replace(/</g, ' '),
        date_of_birth: new Date(hcert.dob),
      }
      if (hcert.v && hcert.v.length) {
        return {
          type: 'vaccination',
          vaccination_date: new Date(hcert.v[0].dt),
          doses_received: hcert.v[0].dn,
          doses_expected: hcert.v[0].sd,
          hash: sha256(hcert.v[0].co+hcert.v[0].ci),
          ...common
        };
      }
      if (hcert.t && hcert.t.length) {
        return {
          type: 'test',
          test_date: new Date(hcert.t[0].sc),
          // 260415000=not detected: http://purl.bioontology.org/ontology/SNOMEDCT/260415000
          is_negative: hcert.t[0].tr === '260415000',
          is_inconclusive: !['260415000', '260373001'].includes(hcert.t[0].tr),
          hash: sha256(hcert.t[0].co+hcert.t[0].ci),
          ...common
        };
      }
      if (hcert.r && hcert.r.length) {
        return {
          type: 'test',
          test_date: new Date(hcert.r[0].fr), // date of positive test
          is_negative: false,
          is_inconclusive: false,
          hash: sha256(hcert.r[0].co+hcert.r[0].ci),
          ...common
        };
      }
      if (hcert.ex) {
        return {
          type: 'exemption',
          ex_date: new Date(hcert.ex.du), // exemption valid until
          hash: sha256(hcert.ex.co+hcert.ex.ci),
          ...common
        };
      }
    },
    async decode2D(qrCode) {
      const ALPHA = {
        regex: 'A-Z\\-\\./ ',
        parse: (s) => s
      };
      const ALPHANUM = {
        regex: '0-9A-Z\\-\\./ ',
        parse: (s) => s
      };
      const NUM = {
        regex: '0-9',
        parse: (s) => parseInt(s)
      };
      const DATE = {
        regex: '0-9',
        parse: (s) => {
          const day = s.substr(0, 2);
          const month = parseInt(s.substr(2, 2), 10)-1;
          const year = s.substr(4, 4);
          const hours = s.substr(8, 2) || '12';
          const minutes = s.substr(10, 2) || '00';
          return new Date(`${year}/${month}/${day} ${hours}:${minutes}`);
        }
      };

      const TEST_FIELDS = [
        { code: 'F0', name: 'tested_first_name', minlen: 0, maxlen: 60, type: ALPHA },
        { code: 'F1', name: 'tested_last_name', minlen: 0, maxlen: 38, type: ALPHA },
        { code: 'F2', name: 'tested_birth_date', minlen: 8, maxlen: 8, type: DATE },
        { code: 'F3', name: 'sex', minlen: 1, maxlen: 1, type: ALPHA },
        { code: 'F4', name: 'analysis_code', minlen: 3, maxlen: 7, type: ALPHANUM },
        { code: 'F5', name: 'analysis_result', minlen: 1, maxlen: 1, type: ALPHA },
        { code: 'F6', name: 'analysis_datetime', minlen: 12, maxlen: 12, type: DATE }
      ];

      const VACCINE_FIELDS = [
        { code: 'L0', name: 'vaccinated_last_name', minlen: 0, maxlen: 80, type: ALPHA },
        { code: 'L1', name: 'vaccinated_first_name', minlen: 0, maxlen: 80, type: ALPHA },
        { code: 'L2', name: 'vaccinated_birth_date', minlen: 8, maxlen: 8, type: DATE },
        { code: 'L3', name: 'disease', minlen: 0, maxlen: 30, type: ALPHANUM },
        { code: 'L4', name: 'prophylactic_agent', minlen: 5, maxlen: 15, type: ALPHANUM },
        { code: 'L5', name: 'vaccine', minlen: 5, maxlen: 30, type: ALPHANUM },
        { code: 'L6', name: 'vaccine_maker', minlen: 5, maxlen: 30, type: ALPHANUM },
        { code: 'L7', name: 'doses_received', minlen: 1, maxlen: 1, type: NUM },
        { code: 'L8', name: 'doses_expected', minlen: 1, maxlen: 1, type: NUM },
        { code: 'L9', name: 'last_dose_date', minlen: 8, maxlen: 8, type: DATE },
        { code: 'LA', name: 'cycle_state', minlen: 2, maxlen: 2, type: ALPHA }
      ];

      const TEST_REGEX = TEST_FIELDS.map((x) => this.fieldRegex(x)).join('');
      const VACCINE_REGEX = VACCINE_FIELDS.map((x) => this.fieldRegex(x)).join('');

      const HEADER_REGEX =
        'DC' +
        '(?<document_version>[0-9]{2})' +
        '(?<certificate_authority_id>[A-Z\\d]{4})' +
        '(?<public_key_id>[A-Z\\d]{4})' +
        '(?<creation_date>[A-Z\\d]{4})' +
        '(?<signature_date>[A-Z\\d]{4})' +
        '(?<document_type>[A-Z\\d]{2})' +
        '(?<document_perimeter>[A-Z\\d]{2})' +
        '(?<document_country>[A-Z]{2})';

      const SIGNATURE_REGEX =
        '\\x1F{1}' + // This character is separating the message from its signature.
        '(?<signature>[A-Z\\d\\=]+)'; // 14 - This is the message signature.

      const TOTAL_REGEX = new RegExp(
        `^(?<data>${HEADER_REGEX}(?:${VACCINE_REGEX}|${TEST_REGEX}))${SIGNATURE_REGEX}$`
      );

      const groups = qrCode.match(TOTAL_REGEX)?.groups;
      if (!groups) throw new Error('Format de certificat invalide');
      const fields = groups.document_type === 'B2' ? TEST_FIELDS : VACCINE_FIELDS;
      const { data, public_key_id, signature } = groups;

      await this.check2DSignature(data, public_key_id, signature);

      const common = {
        first_name: groups.vaccinated_first_name,
        last_name: groups.vaccinated_last_name,
        date_of_birth: this.get2DDate(groups.vaccinated_birth_date),
        certificate_id: groups.code,
      }

      if ('vaccinated_first_name' in groups) {
        return {
          type: 'vaccination',
          vaccination_date: this.get2DDate(groups.last_dose_date),
          doses_received: parseInt(groups.doses_received),
          doses_expected: parseInt(groups.doses_expected),
          ...common
        };
      } else if ('tested_first_name' in cert) {
        return {
          type: 'test',
          test_date: this.get2DDate(groups.analysis_datetime),
          is_negative: groups.analysis_result === 'N',
          is_inconclusive: groups.analysis_result === 'X',
          ...common
        };
      }
    },
    fieldRegex(f) {
      const chars = f.type.regex;
      const terminator = f.minlen !== f.maxlen ? '[\\x1D\\x1E]' : '';
      return `${f.code}(?<${f.name}>[${chars}]{${f.minlen},${f.maxlen}})${terminator}`;
    },
    async key(key_b64) {
      if (!crypto?.subtle) return 'unsupported';
      const key_bin = b64.toByteArray(key_b64);
      return crypto?.subtle.importKey('spki', key_bin, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    },
    async check2DSignature(data, public_key_id, signature_base32) {
      const PUB_KEYS = new Map([
        [
          'AHP1',
          this.key(
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPnxJntwNwme9uHSasmGFFwdC0FWNEpucgzhjr+/AZ6UuTm3kL3ogEUAwKU0tShEVmZNK4/lM05h+0ZvtboJM/A=='
          )
        ],
        [
          'AHP2',
          this.key(
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOYUgmx8pKu0UbyqQ/kt4+PXSpUprkO2YLHmzzoN66XjDW0AnSzXorFPe556p73Vawqaoy3qQKDIDB62IBYWBuA=='
          )
        ],
        [
          'AV01',
          this.key(
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1T9uG2bEP7uWND6RT/lJs2y787BkEJoRMMLXvqPKFFC3ckqFAPnFjbiv/odlWH04a1P9CvaCRxG31FMEOFZyXA=='
          )
        ],
        [
          'AV02',
          this.key(
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3jL6zQ0aQj9eJHUw4VDHB9sMoviLVIlADnoBwC43Md8p9w655z2bDhYEEajQ2amQzt+eU7HdWrvqY23Do91Izg=='
          )
        ]
      ]);

      const public_key_promise = PUB_KEYS.get(public_key_id);
      if (!public_key_promise)
        throw new Error(
          `🤨 Certificat signé par une entité non reconnue ("${public_key_id}"); ` +
          `ce certificat est peut-être contrefait.`
        );
      const public_key = await public_key_promise;
      if (public_key === 'unsupported')
        throw new Error('Votre navigateur ne sait pas vérifier les signatures électroniques');
      const signature = base32Decode(signature_base32, 'RFC4648');
      const data_binary = new TextEncoder().encode(data);
      return this.ecdsaVerify(public_key, signature, data_binary);
    },
    async ecdsaVerify(public_key, signature, data) {
      const valid = await crypto?.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, public_key, signature, data);
      if (!valid) throw new Error('🚨 Signature invalide; ce certificat est peut-être contrefait');
    },
    get2DDate(date_str) {
      const day = date_str.slice(0, 2);
      const month = parseInt(date_str.slice(2, 4), 10)-1;
      const year = date_str.slice(4, 8);

      return new Date(year, month, day)
    }
  },
  beforeDestroy () {
    codeReader.reset();
  },
}
</script>

<style lang="scss">
  .codereader{
    .switchcam{
      width: 30px;
      height: 30px;
      float: right;
      margin-bottom: 10px;
      svg{
        width: 100%;
        height: auto;
        fill: #0088CE;
      }
    }
    label.uploadcustom {
      cursor: pointer;
      display: block;
      text-align: center;
      max-width: calc(100% - 32px);
      width: 100%;
    }
    #upload-photo {
      opacity: 0;
      position: absolute;
      z-index: -1;
    }
    p{
      text-align: center;
      margin: auto;
      margin-bottom: 50px;
      max-width: 335px;
      width: 100%;
    }
    .codereader--video{
      background-color: #333;
      border-radius: 5px;
      overflow: hidden;
      max-width: 335px;
      width: 100%;
      height: 229px;
      margin: auto;
      margin-bottom: 50px;
      video{
        width: 100%;
        height: 100%;
        border: none;
      }
      div {
        color: white;
        width: 80%;
        margin: auto;
        margin-top: 80px;
        text-align: center;
      }
    }
  }
</style>
