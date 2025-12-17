from __future__ import annotations

from unittest.mock import *

import pytest


def test_mocked(subtests: pytest.Subtests):
    from operator import attrgetter, methodcaller

    from ._point import Point, point_values
    from .mocked import mock

    control = point_values()
    mock_point = mock(Point, {'values.return_value': (expect := (1, 2, 3))})

    with subtests.test('control'):
        assert control == (0, 0, 0), 'control should use dataclass defaults'

    with subtests.test('get("values")'):
        mock_values = mock_point.get('values')
        assert isinstance(mock_values, Mock), 'get returns a mock for attributes on the spec'
        assert mock_values.return_value == expect, 'the returned mock should be configured'

    with subtests.test('get("values.return_value")'):
        values_return_value = mock_point.get('values.return_value')
        assert isinstance(values_return_value, tuple), 'get returns the real object for Mock attributes'
        assert values_return_value == expect, 'the mock attribute value should be configured'

    for get in attrgetter('return_value'), methodcaller('__call__'), methodcaller('new'):
        item: NonCallableMagicMock = get(mock_point)
        with subtests.test(str(get).removeprefix('operator.'), name=item._extract_mock_name()):
            assert (from_call := item.values()), 'call result should be truthy'
            assert (from_attr := getattr(item.values, 'return_value', '')), 'return_value should be truthy'
            assert from_call == from_attr, 'values should be consistent across retrieval methods'
            assert all(x == expect for x in (from_call, from_attr)), 'values matches the configured value'

    with subtests.test('mock equality'):
        assert mock_point() == mock_point.return_value, 'mock instances should be cached'

    with subtests.test('patch mock_point'):
        with patch('tests.__lib__._point.Point', mock_point):
            values = point_values()

        assert values != control, 'values called under patch should differ from control'
        assert values == expect, 'values called under patch should match the configured return value'


if __name__ == '__main__':
    pytest.main([__file__])
