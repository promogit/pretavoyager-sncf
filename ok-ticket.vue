<template>
  <div class="screen">
     <div class="app--barnav thx">
       <div class="container container--center">
         <span class="back"><router-link to="/new"><svg width="17" height="17" viewBox="0 0 17 17" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M1.30947 7.82624C0.82776 8.30267 0.831985 9.07697 1.31686 9.55369L7.97658 16.1012C9.13679 17.2614 10.8775 15.5207 9.7173 14.3605L5.83303 10.4762C5.5133 10.1565 5.6216 9.89731 6.07668 9.89731H15.4108C16.0906 9.89731 16.6416 9.34633 16.6416 8.66654C16.6416 7.98674 16.0906 7.43577 15.4108 7.43577H6.07668C5.62239 7.43577 5.51337 7.17654 5.83303 6.85692L9.7173 2.973C10.8775 1.81239 9.13679 0.0720768 7.97658 1.23228L1.30947 7.82624Z" fill="white"></path></svg></router-link></span>
          
          <h1><IconeThx /> {{$CD('OK_HEADER_TITLE')}} <span><EmojGood /></span></h1>
          <p>{{$CD('OK_HEADER_EXPLAIN')}}</p>
      </div>
    </div>        
    <div class="container">
            <p>{{$CD('OK_NOW_YOU_CAN')}}</p>
            <div class="step2">
                <client-only>
                    <LiveDecodePass @done="done"></LiveDecodePass>
                </client-only>
            </div>
            
    </div>
  </div>
</template>
<script>
export default {
  methods: {
    async done(rawString, decodedData) {
      this.$store.commit('setPass', { rawString, decodedData })
      this.$router.replace('/pass-scan')
    },
    isValidAt(hcert, d) {
      let date = new Date(d)
      let validAfter
      let validUntil
      if (hcert.type == 'test') {
        if (hcert.is_negative) {
          validUntil = new Date(hcert.test_date).setHours(
            hcert.test_date.getHours() + 72
          )
        } else {
          validAfter = new Date(hcert.test_date).setDate(
            hcert.test_date.getDate() + 11
          )
          validUntil = new Date(hcert.test_date).setMonth(
            hcert.test_date.getMonth() + 6
          )
        }
      } else if (hcert.type == 'vaccination') {
        if (hcert.doses_received < hcert.doses_expected) {
          return false
        }
        if (hcert.doses_expected > 1) {
          //add 7 days
          validAfter = new Date(hcert.vaccination_date).setDate(
            hcert.vaccination_date.getDate() + 7
          )
        } else {
          //add 28 days
          validAfter = new Date(hcert.vaccination_date).setDate(
            hcert.vaccination_date.getDate() + 28
          )
        }
      } else if(hcert.type == 'exemption') {
        validUntil = new Date(hcert.ex_date);
      }
      if (validAfter && date < validAfter) {
        return false
      }
      if (validUntil && date > validUntil) {
        return false
      }
      return true
    },
  },
}
</script>

<style lang="scss">
    .step2{
        .codereader{
            min-height: calc(100vh - 460px);
        }
    }
</style>