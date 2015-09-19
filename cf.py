import requests
import json
import os

CF_API_ENDPOINT = 'https://api.cloudflare.com/client/v4'


class CFApi(object):

    def __init__(self, auth_mail, auth_key):
        self.auth_mail = auth_mail
        self.cf_api_endpoint = CF_API_ENDPOINT
        self.auth_key = auth_key

    def api_request(self, path, data={}, params=None, method='GET'):
        # Default headers for any request
        cf_headers = dict()
        cf_headers['X-Auth-Email'] = self.auth_mail
        cf_headers['X-Auth-Key'] = self.auth_key
        cf_headers['Content-Type'] = 'application/json'

        try:
            # Send Request
            full_url = self.cf_api_endpoint + path
            if method == 'GET':
                response = requests.get(full_url, headers=cf_headers, params=params).json()
            elif method == 'POST':
                response = requests.post(full_url, data=json.dumps(data), headers=cf_headers, params=params).json()
            elif method == 'PUT':
                response = requests.put(full_url, data=json.dumps(data), headers=cf_headers, params=params).json()
            elif method == 'PATCH':
                response = requests.patch(full_url, data=json.dumps(data), headers=cf_headers, params=params).json()
            elif method == 'DELETE':
                response = requests.delete(full_url, headers=cf_headers, data=json.dumps(data), params=params).json()
            else:
                raise ValueError('Not recognized method: %s' % method)

            # Response
            if response['success']:
                return json.dumps(response['result'])
            else:
                errstr = ""
                for err in response['errors']:
                    errstr += "Error Code: %s - %s\n" % (str(err['code']),str(err['message']))
                raise ValueError(errstr)
        except requests.RequestException as e:
            raise RuntimeError(e)

    # User methods
    def get_user_details(self):
        json_response = self.api_request('/user')
        return json_response

    def update_user(self, first_name=None, last_name=None, telephone=None, country=None, zipcode=None):
        data = {k: v for k, v in (('first_name', first_name),
                                  ('last_name', last_name),
                                  ('telephone', telephone),
                                  ('country', country),
                                  ('zipcode', zipcode)) if v is not None}
        json_response = self.api_request('/user', data=data, method='PATCH')
        return json_response

    # User Billing Profile
    def get_billing_profile(self):
        json_response = self.api_request('/user/billing/profile')
        return json_response

    def create_billing_profile(self, first_name, last_name, address,
                               city, state, zipcode, country,
                               card_number, card_expiry_year,
                               card_expiry_month, card_cvv,
                               address2=None, vat=None):
        required_info = {"first_name": first_name,
                        "last_name": last_name,
                        "address": address,
                        "city": city,
                        "state": state,
                        "zipcode": zipcode,
                        "country": country,
                        "card_number": card_number,
                        "card_expiry_year": card_expiry_year,
                        "card_expiry_month": card_expiry_month,
                        "card_cvv": card_cvv}
        optional_info = {k: v for k, v in (('address2', address2), ('vat', vat)) if v is not None}
        data = required_info.copy()
        data.update(optional_info)
        json_response = self.api_request('/user/billing/profile', data=data, method='POST')
        return json_response

    def update_billing_profile(self, first_name, last_name, address,
                               city, state, zipcode, country,
                               card_number, card_expiry_year,
                               card_expiry_month, card_cvv,
                               address2=None, vat=None):
        required_info = {"first_name": first_name,
                        "last_name": last_name,
                        "address": address,
                        "city": city,
                        "state": state,
                        "zipcode": zipcode,
                        "country": country,
                        "card_number": card_number,
                        "card_expiry_year": card_expiry_year,
                        "card_expiry_month": card_expiry_month,
                        "card_cvv": card_cvv}
        optional_info = {k: v for k, v in (('address2', address2), ('vat', vat)) if v is not None}
        data = required_info.copy()
        data.update(optional_info)
        json_response = self.api_request('/user/billing/profile', data=data, method='PUT')
        return json_response

    def update_vat(self, vat):
        data = {"vat": vat}
        json_response = self.api_request('/user/billing/profile', data=data, method="PATCH")
        return json_response

    def delete_billing_profile(self):
        json_response = self.api_request('/user/billing/profile', method='DELETE')
        return json_response

    def get_user_billing_history(self, page=1,
                             per_page=20,
                             order=None,
                             type=None,
                             occured_at=None,
                             action=None):
        params = {k: v for k, v in (('page', page),
                 ('per_page', per_page),
                 ('order', order),
                 ('type', type),
                 ('occured_at', occured_at),
                 ('action', action)) if v is not None}
        json_response = self.api_request('/user/billing/history', params=params)
        return json_response

    # App Subscription
    def list_app_subscriptions(self, page=1,
                             per_page=20,
                             order=None,
                             status=None,
                             price=None,
                             activated_on=None,
                             expires_on=None,
                             expired_on=None,
                             cancelled_on=None,
                             renewed_on=None,
                             direction=None,
                             match="all"):
        params = {k: v for k, v in (('page', page),
                 ('per_page', per_page),
                 ('order', order),
                 ('status', status),
                 ('price', price),
                 ('activated_on', activated_on),
                 ('expires_on', expires_on),
                 ('expired_on', expired_on),
                 ('cancelled_on', cancelled_on),
                 ('renewed_on', renewed_on),
                 ('direction', direction),
                 ('match', match)) if v is not None}
        json_response = self.api_request('/user/billing/subscriptions/apps', params=params)
        return json_response

    def list_app_info(self, app_id):
        json_response = self.api_request('/user/billing/subscriptions/apps/'+app_id)
        return json_response

    # Zone Subscription
    def list_zone_subscriptions(self, page=1,
                                 per_page=20,
                                 order=None,
                                 status=None,
                                 price=None,
                                 activated_on=None,
                                 expires_on=None,
                                 expired_on=None,
                                 cancelled_on=None,
                                 renewed_on=None,
                                 direction=None,
                                 match="all"):
        params = {k: v for k, v in (('page', page),
                 ('per_page', per_page),
                 ('order', order),
                 ('status', status),
                 ('price', price),
                 ('activated_on', activated_on),
                 ('expires_on', expires_on),
                 ('expired_on', expired_on),
                 ('cancelled_on', cancelled_on),
                 ('renewed_on', renewed_on),
                 ('direction', direction),
                 ('match', match)) if v is not None}
        json_response = self.api_request('/user/billing/subscriptions/zones', params=params)
        return json_response

    def list_zone_info(self, zone_id):
        json_response = self.api_request('/user/billing/subscriptions/apps/'+zone_id)
        return json_response

    # User-level Firewall access rule
    def list_access_rules(self, mode=None,
                                configuration_target=None,
                                configuration_value=None,
                                page=1,
                                per_page=50,
                                order=None,
                                direction=None,
                                match="all"):
        params = {k: v for k, v in (('page', page),
                 ('per_page', per_page),
                 ('order', order),
                 ('mode', mode),
                 ('target', configuration_target),
                 ('value', configuration_value),
                 ('direction', direction),
                 ('match', match)) if v is not None}
        json_response = self.api_request('/user/firewall/access_rules/rules', params=params)
        return json_response

    def create_access_rule(self, mode, conf_target, conf_value, notes=None):
        required_info = {"mode": mode, "configuration": {"target": conf_target, "value": conf_value}}
        if notes is not None:
            optional_info = {"notes": notes}
        else:
            optional_info = {}
        data = required_info.copy()
        data.update(optional_info)
        json_response = self.api_request('/user/firewall/access_rules/rules', method='POST', data=data)
        return json_response

    def update_access_rule(self, rule_id, mode=None, conf_target=None, conf_value=None, notes=None):
        configuration = {k: v for k, v in (('target', conf_target), ('value', conf_value)) if v is not None}
        data = {k: v for k, v in (("mode", mode),
              ("configuration", configuration),
              ("notes", notes)) if v is not None and v is not False}
        json_response = self.api_request('/user/firewall/access_rules/rules/'+ rule_id, method='PATCH', data=data)
        return json_response

    def delete_access_rule(self, rule_id):
        json_response = self.api_request('/user/firewall/access_rules/rules/'+ rule_id, method='DELETE')
        return json_response

    # Zone
    def create_zone(self, name, jump_start=None, organization=None):
        optional_info = {k: v for k, v in (('jump_start', jump_start), ('organization', organization)) if v is not None}
        required_info = {"name": name}
        data = required_info.copy()
        data.update(optional_info)
        json_response = self.api_request('/zones', data=data, method='POST')
        return json_response

    def zone_activiation_check(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/activation_check', method='PUT')
        return json_response

    def list_zones(self, name=None,
                         status=None,
                         page=1,
                         per_page=20,
                         order=None,
                         direction=None,
                         match="all"):
        params = {k: v for k, v in (('status', status),
                 ('name', name),
                 ('page', page),
                 ('per_page', per_page),
                 ('order', order),
                 ('direction', direction),
                 ('match', match)) if v is not None}
        json_response = self.api_request('/zones', params=params, method='GET')
        return json_response

    def get_zone_details(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id)
        return json_response

    def edit_zone_details(self, zone_id, paused=None, vanity_name_servers=None, plan_id=None):
        id = None
        if plan_id is not None:
            id = {"id": plan_id}
        data = {k: v for k, v in (("paused", paused), ('vanity_name_servers', vanity_name_servers), ('plan', id)) if v is not None}
        print data
        json_response = self.api_request('/zones/'+zone_id, data=data, method='PATCH')
        return json_response

    def purge_all_cache_files(self, zone_id):
        data = {'purge_everything': True}
        json_response = self.api_request('/zones/'+zone_id+'/purge_cache', data=data, method='DELETE')
        return json_response

    def purge_file_or_tag(self, zone_id, files=None, tags=None):
        data = {k: v for k, v in (('files',files),('tags',tags)) if v is not None}
        json_response = self.api_request('/zones/'+zone_id+'/purge_cache', data=data, method='DELETE')
        return json_response

    def delete_zone(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id,method="DELETE")
        return json_response

    # Zone Plan
    def list_all_available_plans(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/available_plans')
        return json_response

    def list_plan_details(self, zone_id, plan_id):
        json_response = self.api_request('/zones/'+zone_id+'/available_plans/'+plan_id)
        return json_response

    # Zone Settings
    def list_all_zone_settings(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings')
        return json_response

    def list_zone_advanced_ddos(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/advanced_ddos')
        return json_response

    def list_zone_always_online(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/always_online')
        return json_response

    def list_zone_browser_cache_ttl(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/browser_cache_ttl')
        return json_response

    def list_zone_browser_check(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/browser_check')
        return json_response

    def list_zone_cache_level(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/cache_level')
        return json_response

    def list_zone_challenge_ttl(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/challenge_ttl')
        return json_response

    def list_zone_development_mode(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/development_mode')
        return json_response

    def list_zone_email_obfuscation(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/email_obfuscation')
        return json_response

    def list_zone_hotlink_protection(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/hotlink_protection')
        return json_response

    def list_zone_ip_geolocation(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/ip_geolocation')
        return json_response

    def list_zone_ipv6(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/ipv6')
        return json_response

    def list_zone_minify(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/minify')
        return json_response

    def list_zone_mobile_redirect(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/mobile_redirect')
        return json_response

    def list_zone_mirage(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/mirage')
        return json_response

    def list_zone_origin_error_page_pass_thru(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/origin_error_page_pass_thru')
        return json_response

    def list_zone_polish(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/polish')
        return json_response

    def list_zone_prefetch_preload(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/prefetch_preload')
        return json_response

    def list_zone_response_buffering(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/response_buffering')
        return json_response

    def list_zone_rocket_loader(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/rocket_loader')
        return json_response

    def list_zone_security_header(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/security_header')
        return json_response

    def list_zone_security_level(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/security_level')
        return json_response

    def list_zone_server_side_exclude(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/server_side_exclude')
        return json_response

    def list_zone_sort_query_string_for_cache(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/sort_query_string_for_cache')
        return json_response

    def list_zone_ssl(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/ssl')
        return json_response

    def list_zone_tls_1_2_only(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/tls_1_2_only')
        return json_response

    def list_zone_tls_client_auth(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/tls_client_auth')
        return json_response

    def list_zone_true_client_ip_header(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/true_client_ip_header')
        return json_response

    def list_zone_waf(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/settings/waf')
        return json_response

    def edit_zone_settings_info(self, zone_id, setting_items):
        # array of setting objects
        data = {'items': setting_items}
        json_response = self.api_request('/zones/'+zone_id+'/settings', method="PATCH")
        return json_response

    def change_zone_always_online(self, value="on", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/always_online', data=data, method="PATCH")
        return json_response

    def change_zone_browser_cache_ttl(self, value=14400, zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/browser_cache_ttl', data=data, method="PATCH")
        return json_response

    def change_zone_browser_check(self, value="on", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/browser_check', data=data, method="PATCH")
        return json_response

    def change_zone_cache_level(self, value="aggressive", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/cache_level', data=data, method="PATCH")
        return json_response

    def change_zone_challenge_ttl(self, value=1800, zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/challenge_ttl', data=data, method="PATCH")
        return json_response

    def change_zone_development_mode(self, value="off", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/development_mode', data=data, method="PATCH")
        return json_response

    def change_zone_email_obfuscation(self, value="on", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/email_obfuscation', data=data, method="PATCH")
        return json_response

    def change_zone_hotlink_protection(self, value="off", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/hotlink_protection', data=data, method="PATCH")
        return json_response

    def change_zone_ip_geolocation(self, value="on", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/ip_geolocation', data=data, method="PATCH")
        return json_response

    def change_zone_ipv6(self, value="off", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/ipv6', data=data, method="PATCH")
        return json_response

    def change_zone_minify(self, min_html="off", min_css="off", min_js="off", zone_id):
        data = {"value": {"css": min_css, "html": min_html, "min_js": min_js}}
        json_response = self.api_request('/zones/'+zone_id+'/settings/minify', data=data, method="PATCH")
        return json_response

    def change_zone_mobile_redirect(self, status="off", mobile_subdomain, strip_uri, zone_id):
        data = {"value": {"status": status, "mobile_subdomain": mobile_subdomain, "strip_uri": strip_uri}}
        json_response = self.api_request('/zones/'+zone_id+'/settings/mobile_redirect', data=data, method="PATCH")
        return json_response

    def change_zone_mirage(self, value="off", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/mirage', data=data, method="PATCH")
        return json_response

    def change_zone_origin_error_page_pass_thru(self, value="off", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/origin_error_page_pass_thru', data=data, method="PATCH")
        return json_response

    def change_zone_polish(self, value="off", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/polish', data=data, method="PATCH")
        return json_response

    def change_zone_prefetch_preload(self, value="off", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/prefetch_preload', data=data, method="PATCH")
        return json_response

    def change_zone_response_buffering(self, value="off", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/response_buffering', data=data, method="PATCH")
        return json_response

    def change_zone_rocket_loader(self, value="off", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/rocket_loader', data=data, method="PATCH")
        return json_response

    def change_zone_security_header(self, strict_enabled, strict_max_age, strict_include_subdomains, strict_nosniff, zone_id):
        data = {"value":{"strict_transport_security":
                        {
                         "enabled":strict_enabled,
                         "max_age":strict_max_age,
                         "include_subdomains":strict_include_subdomains,
                         "nosniff":strict_nosniff
                         }
                         }
                }
        json_response = self.api_request('/zones/'+zone_id+'/settings/security_header', data=data, method="PATCH")
        return json_response

    def change_zone_security_level(self, value="medium", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/security_level', data=data, method="PATCH")
        return json_response

    def change_zone_server_side_exclude(self, value="on", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/server_side_exclude', data=data, method="PATCH")
        return json_response

    def change_zone_sort_query_string_for_cache(self, value="off", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/sort_query_string_for_cache', data=data, method="PATCH")
        return json_response

    def change_zone_ssl(self, value="off", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/ssl', data=data, method="PATCH")
        return json_response

    def change_zone_tls_1_2_only(self, value="off", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/tls_1_2_only', data=data, method="PATCH")
        return json_response

    def change_zone_tls_client_auth(self, tls_id="tls_client_auth", tls_value="on", tls_editable=True, tls_modified_on, zone_id):
        data = {"value":
                        {
                        "id":tls_id,
                        "value":tls_value,
                        "editable":tls_editable,
                        "modified_on":tls_modified_on
                        }
                }
        json_response = self.api_request('/zones/'+zone_id+'/settings/tls_client_auth', data=data, method="PATCH")
        return json_response

    def change_zone_true_client_ip_header(self, value="off", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/true_client_ip_header', data=data, method="PATCH")
        return json_response

    def change_zone_waf(self, value="off", zone_id):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/waf', data=data, method="PATCH")
        return json_response

if __name__ == '__main__':
    auth_mail = os.environ.get('CF_AUTH_MAIL')
    auth_key = os.environ.get('CF_AUTH_KEY')
    cf = CFApi(auth_mail, auth_key)
