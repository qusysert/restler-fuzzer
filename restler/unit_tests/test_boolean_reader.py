# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import unittest
from unittest.mock import patch

from engine import dependencies, primitives
from engine.core.requests import Request, RequestCollection
from engine.core.sequences import Sequence
from engine.fuzzing_parameters.body_schema import BodySchema
from engine.fuzzing_parameters.request_params import (
    DynamicObject, ParamBoolean, ParamMember, ParamObject, ParamProperties,
)
from restler_settings import RestlerSettings


class BooleanReaderTest(unittest.TestCase):
    def setUp(self):
        settings = patch.object(RestlerSettings, '_RestlerSettings__instance', None)
        settings.start()
        self.addCleanup(settings.stop)
        RestlerSettings({})

    def schema(self, reader):
        dynamic = DynamicObject(primitives.FUZZABLE_BOOL, 'item_enabled', False) if reader else None
        value = ParamBoolean(param_properties=ParamProperties(), dynamic_object=dynamic)
        value.content = 'item_enabled' if reader else False
        value.tag = 'enabled'
        value.set_fuzzable(False)
        return BodySchema(param=ParamObject([
            ParamMember('enabled', value, param_properties=ParamProperties()),
        ], param_properties=ParamProperties()))

    def test_response_defaults_preserve_boolean_reader(self):
        for response_value in (True, False):
            with self.subTest(response_value=response_value):
                blocks = self.schema(True).fuzz_body_blocks({
                    'use_response_for_default': True,
                    'get_response_values': lambda *args: [response_value],
                })
                request = Request([primitives.restler_static_string("PUT /items HTTP/1.1\r\n\r\n")] + blocks[0])
                rendered, *_ = next(request.render_iter(RequestCollection().candidate_values_pool))
                self.assertIn(dependencies.RDELIM + 'item_enabled' + dependencies.RDELIM, rendered)
                for producer_value in (True, False):
                    with patch.dict(dependencies.tlb, {'item_enabled': producer_value}):
                        body = Sequence([]).resolve_dependencies(rendered)
                        self.assertEqual(json.loads(body.split('\r\n\r\n', 1)[1]), {'enabled': producer_value})

    def test_response_defaults_accept_ordinary_booleans(self):
        for response_value in (True, False):
            with self.subTest(response_value=response_value):
                blocks = self.schema(False).fuzz_body_blocks({
                    'use_response_for_default': True,
                    'get_response_values': lambda *args: [response_value],
                })
                rendered, *_ = next(Request([primitives.restler_static_string("PUT /items HTTP/1.1\r\n\r\n")] + blocks[0]).render_iter(RequestCollection().candidate_values_pool))
                self.assertIsInstance(json.loads(rendered.split('\r\n\r\n', 1)[1])['enabled'], bool)
