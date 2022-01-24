# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_theharvester
# Purpose:      SpiderFoot plug-in for using the 'theHarvester' tool.
#                Tool: https://github.com/laramies/theHarvester
#
# Author:      Sergio Andrea Constantino Noguera <sergio.andreas.cn@gmail.com>
#
# Created:     21/01/2022
# Copyright:   (c) Sergio Andrea Constantino Noguera 2022
# Licence:     GPL
# -------------------------------------------------------------------------------

import requests

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


# noinspection PyPep8Naming
class sfp_tool_theharvester(SpiderFootPlugin):
    meta = {
        'name': 'Tool - theHarvester',
        'summary': ''.join([
            'Determining the threat landscape of a domain on the Internet ',
            'using theHarvester API service.'
        ]),
        'flags': ['tool'],
        'useCases': ['Investigate', 'Passive'],
        'categories': ['Search Engines'],
        'toolDetails': {
            'name': 'theHarvester',
            'description': ''.join([
                'Check the information related to a domain on the Internet, ',
                'which could be gathered as open source intelligence.'
            ]),
            'website': 'https://github.com/laramies/theHarvester',
            'repository': 'https://github.com/laramies/theHarvester'
        }
    }

    # Default options
    opts = {
        'th_host': 'localhost',
        'th_port': '5000',
        'th_sources': 'bing, baidu, duckduckgo, linkedin, sublist3r, twitter, qwant, linkedin_links, otx'
    }

    # Option descriptions
    optdescs = {
        'th_host': 'Host where the theHarvester service is.',
        'th_port': 'Port where the service is exposed.',
        'th_sources': 'theHarvester sources (separated by commas).'
    }

    _watched_event_types = ['DOMAIN_NAME']
    _produced_event_types = ['HUMAN_NAME', 'EMAILADDR', 'DOMAIN_NAME', 'URL_STATIC', 'IP_ADDRESS']

    results = None

    def __init__(self):
        super().__init__()
        self._base_url = None
        self._th_sources = []

    def setup(self, sfc, userOpts=None):
        self.sf = sfc
        self.results = self.tempStorage()

        if userOpts is None:
            userOpts = {}
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

        self._base_url = f'http://{self.opts["th_host"]}:{str(self.opts["th_port"])}'
        for token in self.opts['th_sources'].strip().split(','):
            source = token.strip()
            if len(source) > 0:
                self._th_sources.append(source)

    # What events is this module interested in for input
    def watchedEvents(self):
        return self._watched_event_types

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return self._produced_event_types

    def harvest(self, domain):
        results = requests.get(f'{self._base_url}/query', params={
            'source': ','.join(self._th_sources),
            'domain': domain
        }).json()

        data = {evt_type: set() for evt_type in self._produced_event_types}

        for entity, elements in results.items():
            if entity in ('twitter_people', 'linkedin_people'):
                data['HUMAN_NAME'] |= set(elements)
            elif entity in ('interesting_urls', 'linkedin_links', 'trello_urls'):
                data['URL_STATIC'] |= set(elements)
            elif entity == 'ips':
                data['IP_ADDRESS'] |= set(elements)
            elif entity == 'emails':
                data['EMAILADDR'] |= set(elements)
            elif entity == 'hosts':
                data['DOMAIN_NAME'] |= set(elements)

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        if event.data in self.results:
            self.debug(f'Skipping {event.data}, already checked.')
        else:
            self.results[event.data] = True

            self.sf.debug(f'Received event, {event.eventType}, from {event.module}')

            if event.eventType == 'DOMAIN_NAME' and event.module == 'SpiderFoot UI':
                data = self.harvest(event.data)

                for evt_type, elements in data.items():
                    for artifact in elements:
                        evt = SpiderFootEvent(evt_type, artifact, self.__name__, event)
                        self.notifyListeners(evt)

# End of sfp_new_module class
