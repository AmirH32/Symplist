import unittest
from Symplist import get_study_data, get_treatment_info, get_treatment_data, get_condition_info, check_for_letters, check_for_digits

class test_study_function(unittest.TestCase):
    
    def test_1_get_study_data(self):
        studies = get_study_data('Diabetes')
        self.assertTrue(studies)

    def test_2_get_study_data(self):
        studies = get_study_data('as12354565')
        self.assertFalse(studies)
    
class test_treatment_functions(unittest.TestCase):

    def test_1_get_treatment_info(self):
        treatment_data = get_treatment_info('Aspirin')
        self.assertTrue(treatment_data)
    
    def test_2_get_treatment_info(self):
        treatment_data = get_treatment_info('A12350')
        self.assertFalse(treatment_data)

    def test_1_treatment_data(self):
        treatment_data = get_treatment_data('abcde')
        self.assertFalse(treatment_data)
    
class test_condition_function(unittest.TestCase):
    
    def test_1_get_condition_info(self):
        primary_names, consumer_names, condition_links = get_condition_info('Diabetes')
        self.assertTrue((primary_names and consumer_names) and condition_links)
    
    def test_2_get_condition_info(self):
        primary_names, consumer_names, condition_links = get_condition_info('abcde')
        self.assertFalse((primary_names and consumer_names) and condition_links)
    
class test_checker_functions(unittest.TestCase):

    def test_1_check_for_letters(self):
        self.assertTrue(check_for_letters('A078654839'))
    
    def test_2_check_for_letters(self):
        self.assertTrue(check_for_letters('07CHJ654839'))
    
    def test_3_check_for_letters(self):
        self.assertTrue(check_for_letters('ABDKCLE'))

    def test_4_check_for_letters(self):
        self.assertFalse(check_for_letters('028273!/.'))
    
    def test_1_check_for_digits(self):
        self.assertTrue(check_for_digits('123ksasdno'))
    
    def test_2_check_for_digits(self):
        self.assertTrue(check_for_digits('ksas2dno'))
    
    def test_3_check_for_digits(self):
        self.assertTrue(check_for_digits('12345'))
    
    def test_4_check_for_digits(self):
        self.assertFalse(check_for_digits('abdke!?//asd'))

if __name__ == '__main__':
    unittest.main()