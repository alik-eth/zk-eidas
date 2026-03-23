// Shared credential type configuration used across the demo

export interface FieldDisplay {
  name: string
  label: string
  value: string
}

export interface CredentialTypeConfig {
  id: string
  labelKey: string
  issuerTitleKey: string
  issuerSubtitleKey: string
  credLabelKey: string
  issuer: string
  country: string
  flag: string[]
  flagDir: 'row' | 'col'
  fields: {
    name: string
    labelKey: string
    defaultValue: string
    colSpan?: 2
  }[]
  predicates: {
    id: string
    labelKey: string
    descKey: string
    predicate: { claim: string; op: string; value: any }
    defaultChecked: boolean
  }[]
}

const EU_COUNTRIES = ['UA','DE','FR','IT','ES','PL','NL','BE','AT','SE','CZ','RO','BG','HR','IE','LT','LV','EE','SK','SI','FI','DK','PT','HU','EL','LU','MT','CY']

function epochDaysToday(): number {
  return Math.floor(Date.now() / 86400000)
}

function epochDaysYearsAgo(years: number): number {
  const now = new Date()
  const past = Date.UTC(now.getUTCFullYear() - years, now.getUTCMonth(), now.getUTCDate())
  return Math.floor(past / 86400000)
}

export const CREDENTIAL_TYPES: CredentialTypeConfig[] = [
  {
    id: 'pid',
    labelKey: 'demo.tabPid',
    issuerTitleKey: 'demo.issuerTitlePid',
    issuerSubtitleKey: 'demo.issuerSubtitlePid',
    credLabelKey: 'demo.credLabelPid',
    issuer: 'https://diia.gov.ua',
    country: 'Ukraine',
    flag: ['#005BBB', '#FFD500'],
    flagDir: 'col',
    fields: [
      { name: 'given_name', labelKey: 'demo.fieldGivenName', defaultValue: 'Олександр' },
      { name: 'family_name', labelKey: 'demo.fieldFamilyName', defaultValue: 'Петренко' },
      { name: 'birth_date', labelKey: 'demo.fieldBirthDate', defaultValue: '1998-05-14' },
      { name: 'age_over_18', labelKey: 'demo.fieldAgeOver18', defaultValue: 'true' },
      { name: 'nationality', labelKey: 'demo.fieldNationality', defaultValue: 'UA' },
      { name: 'issuing_country', labelKey: 'demo.fieldIssuingCountry', defaultValue: 'UA' },
      { name: 'resident_country', labelKey: 'demo.fieldResidentCountry', defaultValue: 'UA' },
      { name: 'resident_city', labelKey: 'demo.fieldResidentCity', defaultValue: 'Київ' },
      { name: 'gender', labelKey: 'demo.fieldGender', defaultValue: 'M' },
      { name: 'document_number', labelKey: 'demo.fieldDocNumber', defaultValue: 'UA-1234567890' },
      { name: 'expiry_date', labelKey: 'demo.fieldExpiryDate', defaultValue: '2035-05-14' },
      { name: 'issuing_authority', labelKey: 'demo.fieldIssuingAuthority', defaultValue: 'Міністерство цифрової трансформації', colSpan: 2 },
    ],
    predicates: [
      { id: 'age', labelKey: 'demo.predAge', descKey: 'demo.predAgeDesc', predicate: { claim: 'birth_date', op: 'gte', value: 18 }, defaultChecked: true },
      { id: 'age_over_18', labelKey: 'demo.predAgeOver18', descKey: 'demo.predAgeOver18Desc', predicate: { claim: 'age_over_18', op: 'eq', value: 'true' }, defaultChecked: false },
      { id: 'nationality', labelKey: 'demo.predNat', descKey: 'demo.predNatDesc', predicate: { claim: 'nationality', op: 'set_member', value: EU_COUNTRIES }, defaultChecked: true },
      { id: 'issuing_country', labelKey: 'demo.predIssuingCountry', descKey: 'demo.predIssuingCountryDesc', predicate: { claim: 'issuing_country', op: 'set_member', value: EU_COUNTRIES }, defaultChecked: false },
      { id: 'name', labelKey: 'demo.predName', descKey: 'demo.predNameDesc', predicate: { claim: 'given_name', op: 'eq', value: '__FROM_FORM__' }, defaultChecked: false },
      { id: 'age_lte', labelKey: 'demo.predAgeLte', descKey: 'demo.predAgeLteDesc', predicate: { claim: 'birth_date', op: 'lte', value: 65 }, defaultChecked: false },
      { id: 'doc_valid', labelKey: 'demo.predDocValid', descKey: 'demo.predDocValidDesc', predicate: { claim: 'expiry_date', op: 'gte', value: epochDaysToday() }, defaultChecked: false },
      { id: 'not_revoked', labelKey: 'demo.predNotRevoked', descKey: 'demo.predNotRevokedDesc', predicate: { claim: 'document_number', op: 'neq', value: 'REVOKED' }, defaultChecked: false },
      { id: 'age_range', labelKey: 'demo.predAgeRange', descKey: 'demo.predAgeRangeDesc', predicate: { claim: 'birth_date', op: 'range', value: [18, 65] }, defaultChecked: false },
    ],
  },
  {
    id: 'pid_buyer',
    labelKey: 'demo.tabPid',
    issuerTitleKey: 'demo.issuerTitlePid',
    issuerSubtitleKey: 'demo.issuerSubtitlePid',
    credLabelKey: 'demo.credLabelPid',
    issuer: 'https://diia.gov.ua',
    country: 'Ukraine',
    flag: ['#005BBB', '#FFD500'],
    flagDir: 'col',
    fields: [
      { name: 'given_name', labelKey: 'demo.fieldGivenName', defaultValue: 'Марія' },
      { name: 'family_name', labelKey: 'demo.fieldFamilyName', defaultValue: 'Коваленко' },
      { name: 'birth_date', labelKey: 'demo.fieldBirthDate', defaultValue: '1995-11-03' },
      { name: 'age_over_18', labelKey: 'demo.fieldAgeOver18', defaultValue: 'true' },
      { name: 'nationality', labelKey: 'demo.fieldNationality', defaultValue: 'UA' },
      { name: 'issuing_country', labelKey: 'demo.fieldIssuingCountry', defaultValue: 'UA' },
      { name: 'resident_country', labelKey: 'demo.fieldResidentCountry', defaultValue: 'UA' },
      { name: 'resident_city', labelKey: 'demo.fieldResidentCity', defaultValue: 'Львів' },
      { name: 'gender', labelKey: 'demo.fieldGender', defaultValue: 'F' },
      { name: 'document_number', labelKey: 'demo.fieldDocNumber', defaultValue: 'UA-9876543210' },
      { name: 'expiry_date', labelKey: 'demo.fieldExpiryDate', defaultValue: '2034-11-03' },
      { name: 'issuing_authority', labelKey: 'demo.fieldIssuingAuthority', defaultValue: 'Міністерство цифрової трансформації', colSpan: 2 },
    ],
    predicates: [
      { id: 'age', labelKey: 'demo.predAge', descKey: 'demo.predAgeDesc', predicate: { claim: 'birth_date', op: 'gte', value: 18 }, defaultChecked: true },
      { id: 'age_over_18', labelKey: 'demo.predAgeOver18', descKey: 'demo.predAgeOver18Desc', predicate: { claim: 'age_over_18', op: 'eq', value: 'true' }, defaultChecked: false },
      { id: 'nationality', labelKey: 'demo.predNat', descKey: 'demo.predNatDesc', predicate: { claim: 'nationality', op: 'set_member', value: EU_COUNTRIES }, defaultChecked: true },
      { id: 'issuing_country', labelKey: 'demo.predIssuingCountry', descKey: 'demo.predIssuingCountryDesc', predicate: { claim: 'issuing_country', op: 'set_member', value: EU_COUNTRIES }, defaultChecked: false },
      { id: 'name', labelKey: 'demo.predName', descKey: 'demo.predNameDesc', predicate: { claim: 'given_name', op: 'eq', value: '__FROM_FORM__' }, defaultChecked: false },
      { id: 'age_lte', labelKey: 'demo.predAgeLte', descKey: 'demo.predAgeLteDesc', predicate: { claim: 'birth_date', op: 'lte', value: 65 }, defaultChecked: false },
      { id: 'doc_valid', labelKey: 'demo.predDocValid', descKey: 'demo.predDocValidDesc', predicate: { claim: 'expiry_date', op: 'gte', value: epochDaysToday() }, defaultChecked: false },
      { id: 'not_revoked', labelKey: 'demo.predNotRevoked', descKey: 'demo.predNotRevokedDesc', predicate: { claim: 'document_number', op: 'neq', value: 'REVOKED' }, defaultChecked: false },
      { id: 'age_range', labelKey: 'demo.predAgeRange', descKey: 'demo.predAgeRangeDesc', predicate: { claim: 'birth_date', op: 'range', value: [18, 65] }, defaultChecked: false },
    ],
  },
  {
    id: 'drivers_license',
    labelKey: 'demo.tabDrivers',
    issuerTitleKey: 'demo.issuerTitleDrivers',
    issuerSubtitleKey: 'demo.issuerSubtitleDrivers',
    credLabelKey: 'demo.credLabelDrivers',
    issuer: 'https://ppa.ee',
    country: 'Estonia',
    flag: ['#0072CE', '#000000', '#FFFFFF'],
    flagDir: 'col',
    fields: [
      { name: 'holder_name', labelKey: 'demo.field.holderName', defaultValue: 'Kadri Tamm' },
      { name: 'category', labelKey: 'demo.field.category', defaultValue: 'A, B, C1' },
      { name: 'issue_date', labelKey: 'demo.field.issueDate', defaultValue: '2019-03-22' },
      { name: 'expiry_date', labelKey: 'demo.field.expiryDate', defaultValue: '2034-03-22' },
      { name: 'restrictions', labelKey: 'demo.field.restrictions', defaultValue: 'None' },
      { name: 'license_number', labelKey: 'demo.field.licenseNumber', defaultValue: 'EE-DL-49301150123' },
    ],
    predicates: [
      { id: 'category_b', labelKey: 'demo.predCategoryB', descKey: 'demo.predCategoryBDesc', predicate: { claim: 'category', op: 'eq', value: 'A, B, C1' }, defaultChecked: true },
      { id: 'valid', labelKey: 'demo.predValid', descKey: 'demo.predValidDesc', predicate: { claim: 'expiry_date', op: 'gte', value: epochDaysToday() }, defaultChecked: true },
      { id: 'experienced', labelKey: 'demo.predExperienced', descKey: 'demo.predExperiencedDesc', predicate: { claim: 'issue_date', op: 'lte', value: epochDaysYearsAgo(2) }, defaultChecked: false },
      { id: 'no_restrictions', labelKey: 'demo.predNoRestrictions', descKey: 'demo.predNoRestrictionsDesc', predicate: { claim: 'restrictions', op: 'eq', value: 'None' }, defaultChecked: false },
    ],
  },
  {
    id: 'diploma',
    labelKey: 'demo.tabDiploma',
    issuerTitleKey: 'demo.issuerTitleDiploma',
    issuerSubtitleKey: 'demo.issuerSubtitleDiploma',
    credLabelKey: 'demo.credLabelDiploma',
    issuer: 'https://sorbonne-universite.fr',
    country: 'France',
    flag: ['#002395', '#FFFFFF', '#ED2939'],
    flagDir: 'row',
    fields: [
      { name: 'student_name', labelKey: 'demo.field.studentName', defaultValue: 'Camille Dubois' },
      { name: 'university', labelKey: 'demo.field.university', defaultValue: 'Sorbonne Universit\u00e9' },
      { name: 'degree', labelKey: 'demo.field.degree', defaultValue: 'Master (M2)' },
      { name: 'field_of_study', labelKey: 'demo.field.fieldOfStudy', defaultValue: 'Computer Science' },
      { name: 'graduation_year', labelKey: 'demo.field.graduationYear', defaultValue: '2023' },
      { name: 'diploma_number', labelKey: 'demo.field.diplomaNumber', defaultValue: 'FR-SORB-2023-04521' },
      { name: 'honors', labelKey: 'demo.field.honors', defaultValue: 'Magna Cum Laude' },
    ],
    predicates: [
      { id: 'stem', labelKey: 'demo.predStem', descKey: 'demo.predStemDesc', predicate: { claim: 'field_of_study', op: 'set_member', value: ['Computer Science', 'Mathematics', 'Physics', 'Chemistry', 'Biology', 'Engineering'] }, defaultChecked: true },
      { id: 'recent_grad', labelKey: 'demo.predRecentGrad', descKey: 'demo.predRecentGradDesc', predicate: { claim: 'graduation_year', op: 'gte', value: 2020 }, defaultChecked: true },
      { id: 'masters', labelKey: 'demo.predMasters', descKey: 'demo.predMastersDesc', predicate: { claim: 'degree', op: 'set_member', value: ['Master (M1)', 'Master (M2)', 'PhD'] }, defaultChecked: false },
      { id: 'university_match', labelKey: 'demo.predUniversityMatch', descKey: 'demo.predUniversityMatchDesc', predicate: { claim: 'university', op: 'eq', value: '__FROM_FORM__' }, defaultChecked: false },
    ],
  },
  {
    id: 'student_id',
    labelKey: 'demo.tabStudentId',
    issuerTitleKey: 'demo.issuerTitleStudentId',
    issuerSubtitleKey: 'demo.issuerSubtitleStudentId',
    credLabelKey: 'demo.credLabelStudentId',
    issuer: 'https://uw.edu.pl',
    country: 'Poland',
    flag: ['#FFFFFF', '#DC143C'],
    flagDir: 'col',
    fields: [
      { name: 'student_name', labelKey: 'demo.field.studentName', defaultValue: 'Katarzyna Nowak' },
      { name: 'university', labelKey: 'demo.field.university', defaultValue: 'Uniwersytet Warszawski' },
      { name: 'faculty', labelKey: 'demo.field.faculty', defaultValue: 'Informatyka' },
      { name: 'enrollment_year', labelKey: 'demo.field.enrollmentYear', defaultValue: '2022' },
      { name: 'valid_until', labelKey: 'demo.field.validUntil', defaultValue: '2026-09-30' },
      { name: 'student_number', labelKey: 'demo.field.studentNumber', defaultValue: 'PL-UW-STU-22-31547' },
    ],
    predicates: [
      { id: 'active_student', labelKey: 'demo.predActiveStudent', descKey: 'demo.predActiveStudentDesc', predicate: { claim: 'valid_until', op: 'gte', value: epochDaysToday() }, defaultChecked: true },
      { id: 'enrolled_recently', labelKey: 'demo.predEnrolledRecently', descKey: 'demo.predEnrolledRecentlyDesc', predicate: { claim: 'enrollment_year', op: 'gte', value: 2020 }, defaultChecked: false },
      { id: 'university_match', labelKey: 'demo.predUniversityMatch', descKey: 'demo.predUniversityMatchDesc', predicate: { claim: 'university', op: 'eq', value: '__FROM_FORM__' }, defaultChecked: false },
    ],
  },
  {
    id: 'vehicle',
    labelKey: 'demo.tabVehicle',
    issuerTitleKey: 'demo.issuerTitleVehicle',
    issuerSubtitleKey: 'demo.issuerSubtitleVehicle',
    credLabelKey: 'demo.credLabelVehicle',
    issuer: 'https://kba.de',
    country: 'Germany',
    flag: ['#000000', '#DD0000', '#FFCC00'],
    flagDir: 'col',
    fields: [
      { name: 'owner_name', labelKey: 'demo.field.ownerName', defaultValue: 'Maximilian Schneider' },
      { name: 'owner_document_number', labelKey: 'demo.field.ownerDocNumber', defaultValue: 'UA-1234567890' },
      { name: 'plate_number', labelKey: 'demo.field.plateNumber', defaultValue: 'B-MS 2847' },
      { name: 'make_model', labelKey: 'demo.field.makeModel', defaultValue: 'Volkswagen Golf' },
      { name: 'vin', labelKey: 'demo.field.vin', defaultValue: 'WVWZZZ1JZYW000001' },
      { name: 'insurance_expiry', labelKey: 'demo.field.insuranceExpiry', defaultValue: '2027-01-15' },
      { name: 'registration_date', labelKey: 'demo.field.registrationDate', defaultValue: '2021-06-10' },
    ],
    predicates: [
      { id: 'insured', labelKey: 'demo.predInsured', descKey: 'demo.predInsuredDesc', predicate: { claim: 'insurance_expiry', op: 'gte', value: epochDaysToday() }, defaultChecked: true },
      { id: 'eu_type', labelKey: 'demo.predEuType', descKey: 'demo.predEuTypeDesc', predicate: { claim: 'make_model', op: 'set_member', value: ['Volkswagen Golf', 'BMW 3 Series', 'Toyota Corolla', 'Renault Clio', 'Fiat 500'] }, defaultChecked: true },
      { id: 'vin_active', labelKey: 'demo.predVinActive', descKey: 'demo.predVinActiveDesc', predicate: { claim: 'vin', op: 'neq', value: 'REVOKED' }, defaultChecked: false },
    ],
  },
]
