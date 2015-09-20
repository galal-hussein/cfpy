import requests
import json
import os

CF_API_ENDPOINT = 'https://api.cloudflare.com/client/v4'


class CFapi(object):

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
        data = {"first_name": first_name,
                "last_name": last_name,
                "address": address,
                "city": city,
                "state": state,
                "zipcode": zipcode,
                "country": country,
                "card_number": card_number,
                "card_expiry_year": card_expiry_year,
                "card_expiry_month": card_expiry_month,
                "card_cvv": card_cvv,
                "address2": address2,
                "vat": vat}
        json_response = self.api_request('/user/billing/profile', data=data, method='POST')
        return json_response

    def update_billing_profile(self, first_name, last_name, address,
                               city, state, zipcode, country,
                               card_number, card_expiry_year,
                               card_expiry_month, card_cvv,
                               address2=None, vat=None):
        data = {"first_name": first_name,
                        "last_name": last_name,
                        "address": address,
                        "city": city,
                        "state": state,
                        "zipcode": zipcode,
                        "country": country,
                        "card_number": card_number,
                        "card_expiry_year": card_expiry_year,
                        "card_expiry_month": card_expiry_month,
                        "card_cvv": card_cvv,
                        "address2": address2,
                        "vat": vat}
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
        data = {"mode": mode, "configuration": {"target": conf_target, "value": conf_value}, "notes": notes}
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
        data = {"name": name, "jump_start": jump_start, "organization": organization}
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
        json_response = self.api_request('/zones', params=params)
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

    def change_zone_always_online(self, zone_id, value="on"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/always_online', data=data, method="PATCH")
        return json_response

    def change_zone_browser_cache_ttl(self, zone_id, value=14400):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/browser_cache_ttl', data=data, method="PATCH")
        return json_response

    def change_zone_browser_check(self, zone_id, value="on"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/browser_check', data=data, method="PATCH")
        return json_response

    def change_zone_cache_level(self, zone_id, value="aggressive"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/cache_level', data=data, method="PATCH")
        return json_response

    def change_zone_challenge_ttl(self, zone_id, value=1800):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/challenge_ttl', data=data, method="PATCH")
        return json_response

    def change_zone_development_mode(self, zone_id, value="off"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/development_mode', data=data, method="PATCH")
        return json_response

    def change_zone_email_obfuscation(self, zone_id, value="on"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/email_obfuscation', data=data, method="PATCH")
        return json_response

    def change_zone_hotlink_protection(self, zone_id, value="off"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/hotlink_protection', data=data, method="PATCH")
        return json_response

    def change_zone_ip_geolocation(self, zone_id, value="on"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/ip_geolocation', data=data, method="PATCH")
        return json_response

    def change_zone_ipv6(self, zone_id, value="off"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/ipv6', data=data, method="PATCH")
        return json_response

    def change_zone_minify(self, zone_id, min_html="off", min_css="off", min_js="off"):
        data = {"value": {"css": min_css, "html": min_html, "min_js": min_js}}
        json_response = self.api_request('/zones/'+zone_id+'/settings/minify', data=data, method="PATCH")
        return json_response

    def change_zone_mobile_redirect(self, mobile_subdomain, strip_uri, zone_id, status="off"):
        data = {"value": {"status": status, "mobile_subdomain": mobile_subdomain, "strip_uri": strip_uri}}
        json_response = self.api_request('/zones/'+zone_id+'/settings/mobile_redirect', data=data, method="PATCH")
        return json_response

    def change_zone_mirage(self, zone_id, value="off"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/mirage', data=data, method="PATCH")
        return json_response

    def change_zone_origin_error_page_pass_thru(self, zone_id, value="off"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/origin_error_page_pass_thru', data=data, method="PATCH")
        return json_response

    def change_zone_polish(self, zone_id, value="off"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/polish', data=data, method="PATCH")
        return json_response

    def change_zone_prefetch_preload(self, zone_id, value="off"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/prefetch_preload', data=data, method="PATCH")
        return json_response

    def change_zone_response_buffering(self, zone_id, value="off"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/response_buffering', data=data, method="PATCH")
        return json_response

    def change_zone_rocket_loader(self, zone_id, value="off"):
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

    def change_zone_security_level(self, zone_id, value="medium"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/security_level', data=data, method="PATCH")
        return json_response

    def change_zone_server_side_exclude(self, zone_id, value="on"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/server_side_exclude', data=data, method="PATCH")
        return json_response

    def change_zone_sort_query_string_for_cache(self, zone_id, value="off"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/sort_query_string_for_cache', data=data, method="PATCH")
        return json_response

    def change_zone_ssl(self, zone_id, value="off"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/ssl', data=data, method="PATCH")
        return json_response

    def change_zone_tls_1_2_only(self, zone_id, value="off"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/tls_1_2_only', data=data, method="PATCH")
        return json_response

    def change_zone_tls_client_auth(self, tls_modified_on, zone_id, tls_id="tls_client_auth", tls_value="on", tls_editable=True):
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

    def change_zone_true_client_ip_header(self, zone_id, value="off"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/true_client_ip_header', data=data, method="PATCH")
        return json_response

    def change_zone_waf(self, zone_id, value="off"):
        data = {"value": value}
        json_response = self.api_request('/zones/'+zone_id+'/settings/waf', data=data, method="PATCH")
        return json_response

    # DNS Records for a Zone
    def create_dns_record(self, zone_id, type, name, content, ttl=None):
        data = {"type": type, "name": name, "content": content, "ttl": None}
        json_response = self.api_request('/zones/'+zone_id+'/dns_records', data=data, method="POST")
        return json_response

    def list_dns_records(self, zone_id,
                              type=None,
                              name=None,
                              content=None,
                              page=1,
                              per_page=50,
                              order=None,
                              direction=None,
                              match="all"):
        params = {k: v for k, v in (('page', page),
                 ('per_page', per_page),
                 ('order', order),
                 ('type', type),
                 ('name', name),
                 ('content', content),
                 ('direction', direction),
                 ('match', match)) if v is not None}
        json_response = self.api_request('/zones/'+zone_id+'/dns_records', params=params)
        return json_response

    def dns_record_details(self, zone_id, record_id):
        json_response = self.api_request('/zones/'+zone_id+'/dns_records/'+ record_id)
        return json_response

    # def update_dns_record(self, zone_id, record_id, ):

    def delete_dns_record(self, zone_id, record_id):
        json_response = self.api_request('/zones/'+zone_id+'/dns_records/'+ record_id, method="DELETE")
        return json_response

    # Railgun connections for a Zone
    def get_available_zone_railguns(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/railguns')
        return json_response

    def get_railgun_zone_details(self, zone_id, railgun_id):
        json_response = self.api_request('/zones/'+zone_id+'/railguns/'+railgun_id)
        return json_response

    def test_railgun_zone_connection(self, zone_id, railgun_id):
        json_response = self.api_request('/zones/'+zone_id+'/railguns/'+railgun_id+'/diagnose')
        return json_response

    def connect_to_zone_railgun(self, zone_id, railgun_id):
        data = {"connected": True}
        json_response = self.api_request('/zones/'+zone_id+'/railguns/'+railgun_id, method='PATCH')
        return json_response

    def disconnect_to_zone_railgun(self, zone_id, railgun_id):
        data = {"connected": False}
        json_response = self.api_request('/zones/'+zone_id+'/railguns/'+railgun_id, method='PATCH')
        return json_response

    # Zone Analytics
    def dashboard_view(self, zone_id,  exclude_series, since=-10080, until=0, continuous=True):
        params = {k: v for k, v in (('since', since),
                 ('until', until),
                 ('continuous', continuous),
                 ('exclude_series', exclude_series)) if v is not None}
        json_response = self.api_request('/zones/'+zone_id+'/analytics/dashboard', params=params)
        return json_response

    def dashboard_view_by_colos(self, zone_id,  exclude_series, since=-10080, until=0, continuous=True):
        params = {k: v for k, v in (('since', since),
                 ('until', until),
                 ('continuous', continuous),
                 ('exclude_series', exclude_series)) if v is not None}
        json_response = self.api_request('/zones/'+zone_id+'/analytics/colos', params=params)
        return json_response

    # Railguns
    def create_railgun(self, name):
        data = {"name": name}
        json_response = self.api_request('/railguns', data=data, method="POST")
        return json_response

    def list_all_railguns(self, page=1, per_page=20, direction=None):
        params = {k: v for k, v in (('page', page),
        ('per_page', per_page),
        ('direction', direction)) if v is not None}
        json_response = self.api_request('/railguns', params=params)

    def get_railgun_details(self, railgun_id):
        json_response = self.api_request('/railguns/'+railgun_id)
        return json_response

    def get_zones_connected_to_railguns(self, railgun_id):
        json_response = self.api_request('/railguns/'+railgun_id+'/zones')
        return json_response

    def enable_railgun(self, railgun_id):
        data = {"enabled": True}
        json_response = self.api_request('/railguns/'+railgun_id, data=data, method="PATCH")
        return json_response

    def disable_railgun(self, railgun_id):
        data = {"enabled": False}
        json_response = self.api_request('/railguns/'+railgun_id, data=data, method="PATCH")
        return json_response

    def disable_railgun(self, railgun_id):
        json_response = self.api_request('/railguns/'+railgun_id, method="DELETE")

    # Custom Pages for a Zone
    def get_available_custom_pages(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/custom_pages')
        return json_response

    def get_custom_page_details(self, zone_id, page_id):
        json_response = self.api_request('/zones/'+zone_id+'/custom_pages/'+page_id)
        return json_response

    def update_custom_page_url(self, zone_id, page_id, url, state):
        data = {'url': url, 'state': state}
        json_response = self.api_request('/zones/'+zone_id+'/custom_pages/'+page_id, data=data, method="PUT")
        return json_response

    # Custom SSL for a Zone
    def create_ssl_configuration(self, zone_id, certificate, private_key, bundle_method='ubiquitous'):
        data = {"certificate": certificate, "private_key": private_key, "bundle_method": bundle_method}
        json_response = self.api_request('/zones/'+zone_id+'/custom_certificates', data=data, method="POST")
        return json_response

    def list_ssl_configuration(self, zone_id, status=None, page=1, per_page=20, order='priority', direction=None, match='all'):
        params = {k: v for k, v in (('page', page),
                 ('per_page', per_page),
                 ('order', order),
                 ('status', status),
                 ('direction', direction),
                 ('match', match)) if v is not None}
        json_response = self.api_request('/zones/'+zone_id+'/custom_certificates', params=params)
        return json_response

    def get_ssl_configuration_details(self, zone_id, cert_id):
        json_response = self.api_request('/zones/'+zone_id+'/custom_certificates/'+cert_id)
        return json_response

    def update_ssl_configuration(self, zone_id, cert_id, certificate, private_key, bundle_method='ubiquitous'):
        data = {"certificate": certificate, "private_key": private_key, "bundle_method": bundle_method}
        json_response = self.api_request('/zones/'+zone_id+'/custom_certificates/'+ cert_id, data=data, method='PATCH')
        return json_response

    def reprioritize_ssl_certificates(self, zone_id, ssl_certs):
        data = {'certificates': ssl_certs}
        json_response = self.api_request('/zones/'+zone_id+'/custom_certificates/prioritize', data=data, method="PUT")
        return json_response

    def delete_ssl_certificate(self, zone_id, cert_id):
        json_response = self.api_request('/zones/'+zone_id+'/custom_certificates/'+cert_id, method='DELETE')
        return json_response

    # Keyless SSL for a Zone
    def create_keyless_ssl_configuration(self, zone_id, host, name, certificate, port=24008, bundle_method='ubiquitous'):
        data = {
            'host': host,
            'port': port,
            'name': name,
            'certificate': certificate,
            'bundle_method': bundle_method
        }
        json_response = self.api_request('/zones/'+zone_id+'/keyless_certificates', data=data, method='POST')
        return json_response

    def list_keyless_ssl_configurations(self, zone_id):
        json_response = self.api_request('/zones/'+zone_id+'/keyless_certificates')
        return json_response

    def get_keyless_ssl_details(self, zone_id, cert_id):
        json_response = self.api_request('/zones/'+zone_id+'/keyless_certificates/'+cert_id)
        return json_response

    def update_keyless_configuration(self, zone_id, conf_id, host, name, port=24008, enabled=None):
        data = {
            'host': host,
            'port': port,
            'name': name,
            'enabled': enabled
        }
        json_response = self.api_request('/zones/'+zone_id+'/keyless_certificates/'+conf_id, data=data, method='PATCH')
        return json_response

    def delete_keyless_configuration(self, zone_id, conf_id):
        json_response = self.api_request('/zones/'+zone_id+'/keyless_certificates/'+conf_id, method='DELETE')
        return json_response

    # Firewall access rule for a Zone
    def list_zone_access_rules(self, zone_id,
                                     scope_type=None,
                                     mode=None,
                                     configuration_target=None,
                                     configuration_value=None,
                                     page=1,
                                     per_page=20,
                                     order=None,
                                     direction=None,
                                     match="all"):
        data = {
            'scope_type': scope_type,
            'mode': mode,
            'configuration_target': configuration_target,
            'configuration_value': configuration_value,
            'page': page,
            'per_page': per_page,
            'order': order,
            'direction': direction,
            'match': match
        }
        json_response = self.api_request('/zones/'+zone_id+'/firewall/access_rules/rules', data=data)
        return json_response

    def create_access_rule(self, zone_id, mode, conf_target, conf_value, notes=None):
        data = {"mode": mode, "configuration": {"target": conf_target, "value": conf_value}, "notes": notes}
        json_response = self.api_request('/zones/'+zone_id+'/firewall/access_rules/rules', data=data, method='POST')
        return json_response

    def update_access_rule(self, zone_id, rule_id, mode=None, notes=None):
        data = {
            'mode': mode,
            'notes': notes
        }
        json_response = self.api_request('/zones/'+zone_id+'/firewall/access_rules/rules/'+rule_id, data=data, method="PATCH")
        return json_response

    def delete_access_rule(self, zone_id, rule_id, cascade="none"):
        data = {"cascade": cascade}
        json_response = self.api_request('/zones/'+zone_id+'/firewall/access_rules/rules/'+rule_id, data=data, method="DELETE")
        return json_response

if __name__ == '__main__':
    auth_mail = os.environ.get('CF_AUTH_MAIL')
    auth_key = os.environ.get('CF_AUTH_KEY')
    cf = CFapi(auth_mail, auth_key)
