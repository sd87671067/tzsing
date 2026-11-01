import unittest
from inbound_inventory import inbound_inventory

class InboundRoutes(unittest.TestCase):
    def config(self,rules):
        return {'inbounds':[{'tag':t,'type':'vless'} for t in ('a','b')]+[{'tag':'internal','type':'socks'}], 'outbounds':[{'type':'direct','tag':'direct'}], 'route':{'rules':rules,'final':'direct'}}
    def test_shared_direct_and_internal_exclusion(self):
        a=inbound_inventory(self.config([]));self.assertEqual([x['tag'] for x in a],['a','b']);self.assertTrue(all(x['routes']==['direct'] and not x['unknown'] for x in a))
    def test_conditional_and_ruleset(self):
        a=inbound_inventory(self.config([{'inbound':['a'],'auth_user':['user'],'outbound':'proxy'},{'rule_set':['geo'],'outbound':'other'}]));self.assertEqual(a[0]['routes'],['direct','other','proxy']);self.assertEqual(a[1]['routes'],['direct','other'])
    def test_reject_before_route(self):
        a=inbound_inventory(self.config([{'inbound':['a'],'action':'reject'},{'inbound':['a'],'outbound':'proxy'}]));self.assertTrue(a[0]['unknown']);self.assertEqual(a[0]['routes'],[]);self.assertEqual(a[1]['routes'],['direct'])
    def test_exact_route_and_sniff(self):
        a=inbound_inventory(self.config([{'action':'sniff'},{'inbound':['a'],'outbound':'proxy'}]));self.assertEqual(a[0]['routes'],['proxy']);self.assertFalse(a[0]['unknown'])
    def test_logical_and_inverted_unknown(self):
        a=inbound_inventory(self.config([{'type':'logical','mode':'and','rules':[{'inbound':['a']},{'domain':['example.org']}],'outbound':'proxy'}]));self.assertEqual(a[0]['routes'],['direct','proxy']);self.assertEqual(a[1]['routes'],['direct','proxy'])

if __name__=='__main__':unittest.main()
