import copy,unittest
from inbound_inventory import inbound_inventory,auth_id
class Rules(unittest.TestCase):
 def test_precise_rules_and_display_names(self):
  users=[{'name':'alice','uuid':'00000000-0000-4000-8000-000000000001'},{'name':'bob','uuid':'00000000-0000-4000-8000-000000000002'}]
  rules=[{'inbound':['shared'],'auth_user':[u['name']],'action':'route','outbound':'direct'} for u in users]
  c={'inbounds':[{'type':'vless','tag':'shared','users':users}],'route':{'rules':rules}}
  i=inbound_inventory(c)[0];self.assertEqual(len(i['auth_ids']),2);self.assertEqual(len(i['rule_bindings']),2);self.assertEqual(sorted(i['auth_names'].values()),['alice','bob'])
  before=i['auth_ids'];c['inbounds'][0]['users'][0]['name']='new';self.assertEqual(inbound_inventory(c)[0]['auth_ids'],before)
  # No fuzzy matching, conditions, duplicate authentication names or unsafe
  # String() metacharacters can introduce an identity proof.
  c['inbounds'][0]['users'][0]['name']='alice';c['route']['rules'][0]['domain_suffix']=['example.org']
  self.assertEqual(len(inbound_inventory(c)[0]['rule_bindings']),1)
  c['inbounds'][0]['users'][1]['name']='alice';self.assertFalse(inbound_inventory(c)[0]['rule_bindings'])
if __name__=='__main__':unittest.main()
