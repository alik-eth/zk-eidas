// Shared credential type configuration used across the demo

export interface FieldDisplay {
  name: string
  label: string
  value: string
}

export interface CredentialVariant {
  fields: { name: string; labelKey: string; defaultValue: string; colSpan?: 2 }[]
  issuer: string
  country: string
  flag: string[]
  flagDir: 'row' | 'col'
  issuerTitleKey: string
  issuerSubtitleKey: string
  secondary?: {
    fields: { name: string; labelKey: string; defaultValue: string; colSpan?: 2 }[]
  }
}

export interface CredentialTypeConfig {
  id: string
  labelKey: string
  credLabelKey: string
  variants: { ua: CredentialVariant; eu: CredentialVariant }
  predicates: {
    id: string
    labelKey: string
    descKey: string
    predicate: { claim: string; op: string; value: any }
    defaultChecked: boolean
  }[]
}

export function resolveVariant(
  config: CredentialTypeConfig,
  locale: 'uk' | 'en',
  isSecondary?: boolean,
): CredentialVariant {
  const variant = locale === 'uk' ? config.variants.ua : config.variants.eu
  if (isSecondary && variant.secondary) {
    return { ...variant, fields: variant.secondary.fields }
  }
  return variant
}

const EU_COUNTRIES = ['UA','DE','FR','IT','ES','PL','NL','BE','AT','SE','CZ','RO','BG','HR','IE','LT','LV','EE','SK','SI','FI','DK','PT','HU','EL','LU','MT','CY']

// Longfellow uses lexicographic CBOR comparison — dates are ISO strings, not epoch days
function isoDateToday(): string {
  return new Date().toISOString().slice(0, 10)
}

function isoDateYearsAgo(years: number): string {
  const now = new Date()
  return new Date(Date.UTC(now.getUTCFullYear() - years, now.getUTCMonth(), now.getUTCDate()))
    .toISOString().slice(0, 10)
}

export const CREDENTIAL_TYPES: CredentialTypeConfig[] = [
  {
    id: 'pid',
    labelKey: 'sandbox.tabPid',
    credLabelKey: 'sandbox.credLabelPid',
    variants: {
      ua: {
        fields: [
          { name: 'given_name', labelKey: 'sandbox.fieldGivenName', defaultValue: 'Олександр' },
          { name: 'family_name', labelKey: 'sandbox.fieldFamilyName', defaultValue: 'Петренко' },
          { name: 'birth_date', labelKey: 'sandbox.fieldBirthDate', defaultValue: '1998-05-14' },
          { name: 'age_over_18', labelKey: 'sandbox.fieldAgeOver18', defaultValue: 'true' },
          { name: 'nationality', labelKey: 'sandbox.fieldNationality', defaultValue: 'UA' },
          { name: 'issuing_country', labelKey: 'sandbox.fieldIssuingCountry', defaultValue: 'UA' },
          { name: 'resident_country', labelKey: 'sandbox.fieldResidentCountry', defaultValue: 'UA' },
          { name: 'resident_city', labelKey: 'sandbox.fieldResidentCity', defaultValue: 'Київ' },
          { name: 'gender', labelKey: 'sandbox.fieldGender', defaultValue: 'M' },
          { name: 'document_number', labelKey: 'sandbox.fieldDocNumber', defaultValue: 'UA-1234567890' },
          { name: 'expiry_date', labelKey: 'sandbox.fieldExpiryDate', defaultValue: '2035-05-14' },
          { name: 'issuing_authority', labelKey: 'sandbox.fieldIssuingAuthority', defaultValue: 'Міністерство цифрової трансформації', colSpan: 2 },
        ],
        issuer: 'https://diia.gov.ua',
        country: 'Ukraine',
        flag: ['#005BBB', '#FFD500'],
        flagDir: 'col',
        issuerTitleKey: 'sandbox.issuerTitlePid',
        issuerSubtitleKey: 'sandbox.issuerSubtitlePid',
        secondary: {
          fields: [
            { name: 'given_name', labelKey: 'sandbox.fieldGivenName', defaultValue: 'Марія' },
            { name: 'family_name', labelKey: 'sandbox.fieldFamilyName', defaultValue: 'Коваленко' },
            { name: 'birth_date', labelKey: 'sandbox.fieldBirthDate', defaultValue: '1995-11-03' },
            { name: 'age_over_18', labelKey: 'sandbox.fieldAgeOver18', defaultValue: 'true' },
            { name: 'nationality', labelKey: 'sandbox.fieldNationality', defaultValue: 'UA' },
            { name: 'issuing_country', labelKey: 'sandbox.fieldIssuingCountry', defaultValue: 'UA' },
            { name: 'resident_country', labelKey: 'sandbox.fieldResidentCountry', defaultValue: 'UA' },
            { name: 'resident_city', labelKey: 'sandbox.fieldResidentCity', defaultValue: 'Львів' },
            { name: 'gender', labelKey: 'sandbox.fieldGender', defaultValue: 'F' },
            { name: 'document_number', labelKey: 'sandbox.fieldDocNumber', defaultValue: 'UA-9876543210' },
            { name: 'expiry_date', labelKey: 'sandbox.fieldExpiryDate', defaultValue: '2034-11-03' },
            { name: 'issuing_authority', labelKey: 'sandbox.fieldIssuingAuthority', defaultValue: 'Міністерство цифрової трансформації', colSpan: 2 },
          ],
        },
      },
      eu: {
        fields: [
          { name: 'given_name', labelKey: 'sandbox.fieldGivenName', defaultValue: 'Maximilian' },
          { name: 'family_name', labelKey: 'sandbox.fieldFamilyName', defaultValue: 'Schneider' },
          { name: 'birth_date', labelKey: 'sandbox.fieldBirthDate', defaultValue: '1998-05-14' },
          { name: 'age_over_18', labelKey: 'sandbox.fieldAgeOver18', defaultValue: 'true' },
          { name: 'nationality', labelKey: 'sandbox.fieldNationality', defaultValue: 'DE' },
          { name: 'issuing_country', labelKey: 'sandbox.fieldIssuingCountry', defaultValue: 'DE' },
          { name: 'resident_country', labelKey: 'sandbox.fieldResidentCountry', defaultValue: 'DE' },
          { name: 'resident_city', labelKey: 'sandbox.fieldResidentCity', defaultValue: 'Berlin' },
          { name: 'gender', labelKey: 'sandbox.fieldGender', defaultValue: 'M' },
          { name: 'document_number', labelKey: 'sandbox.fieldDocNumber', defaultValue: 'DE-1234567890' },
          { name: 'expiry_date', labelKey: 'sandbox.fieldExpiryDate', defaultValue: '2035-05-14' },
          { name: 'issuing_authority', labelKey: 'sandbox.fieldIssuingAuthority', defaultValue: 'Bundesdruckerei GmbH', colSpan: 2 },
        ],
        issuer: 'https://bundesdruckerei.de',
        country: 'Germany',
        flag: ['#000000', '#DD0000', '#FFCC00'],
        flagDir: 'col',
        issuerTitleKey: 'sandbox.issuerTitlePidDe',
        issuerSubtitleKey: 'sandbox.issuerSubtitlePidDe',
        secondary: {
          fields: [
            { name: 'given_name', labelKey: 'sandbox.fieldGivenName', defaultValue: 'Sophie' },
            { name: 'family_name', labelKey: 'sandbox.fieldFamilyName', defaultValue: 'Müller' },
            { name: 'birth_date', labelKey: 'sandbox.fieldBirthDate', defaultValue: '1995-11-03' },
            { name: 'age_over_18', labelKey: 'sandbox.fieldAgeOver18', defaultValue: 'true' },
            { name: 'nationality', labelKey: 'sandbox.fieldNationality', defaultValue: 'DE' },
            { name: 'issuing_country', labelKey: 'sandbox.fieldIssuingCountry', defaultValue: 'DE' },
            { name: 'resident_country', labelKey: 'sandbox.fieldResidentCountry', defaultValue: 'DE' },
            { name: 'resident_city', labelKey: 'sandbox.fieldResidentCity', defaultValue: 'München' },
            { name: 'gender', labelKey: 'sandbox.fieldGender', defaultValue: 'F' },
            { name: 'document_number', labelKey: 'sandbox.fieldDocNumber', defaultValue: 'DE-9876543210' },
            { name: 'expiry_date', labelKey: 'sandbox.fieldExpiryDate', defaultValue: '2034-11-03' },
            { name: 'issuing_authority', labelKey: 'sandbox.fieldIssuingAuthority', defaultValue: 'Bundesdruckerei GmbH', colSpan: 2 },
          ],
        },
      },
    },
    predicates: [
      { id: 'age', labelKey: 'sandbox.predAge', descKey: 'sandbox.predAgeDesc', predicate: { claim: 'birth_date', op: 'gte', value: 18 }, defaultChecked: true },
      { id: 'age_over_18', labelKey: 'sandbox.predAgeOver18', descKey: 'sandbox.predAgeOver18Desc', predicate: { claim: 'age_over_18', op: 'eq', value: 'true' }, defaultChecked: false },
      { id: 'nationality', labelKey: 'sandbox.predNat', descKey: 'sandbox.predNatDesc', predicate: { claim: 'nationality', op: 'set_member', value: EU_COUNTRIES }, defaultChecked: true },
      { id: 'issuing_country', labelKey: 'sandbox.predIssuingCountry', descKey: 'sandbox.predIssuingCountryDesc', predicate: { claim: 'issuing_country', op: 'set_member', value: EU_COUNTRIES }, defaultChecked: false },
      { id: 'name', labelKey: 'sandbox.predName', descKey: 'sandbox.predNameDesc', predicate: { claim: 'given_name', op: 'eq', value: '__FROM_FORM__' }, defaultChecked: false },
      { id: 'age_lte', labelKey: 'sandbox.predAgeLte', descKey: 'sandbox.predAgeLteDesc', predicate: { claim: 'birth_date', op: 'lte', value: 65 }, defaultChecked: false },
      { id: 'doc_valid', labelKey: 'sandbox.predDocValid', descKey: 'sandbox.predDocValidDesc', predicate: { claim: 'expiry_date', op: 'gte', value: isoDateToday() }, defaultChecked: false },
      { id: 'not_revoked', labelKey: 'sandbox.predNotRevoked', descKey: 'sandbox.predNotRevokedDesc', predicate: { claim: 'document_number', op: 'neq', value: 'REVOKED' }, defaultChecked: false },
      { id: 'age_range', labelKey: 'sandbox.predAgeRange', descKey: 'sandbox.predAgeRangeDesc', predicate: { claim: 'birth_date', op: 'range', value: [18, 65] }, defaultChecked: false },
    ],
  },
  {
    id: 'drivers_license',
    labelKey: 'sandbox.tabDrivers',
    credLabelKey: 'sandbox.credLabelDrivers',
    variants: {
      ua: {
        fields: [
          { name: 'holder_name', labelKey: 'sandbox.field.holderName', defaultValue: 'Андрій Мельник' },
          { name: 'category', labelKey: 'sandbox.field.category', defaultValue: 'A, B, C1' },
          { name: 'issue_date', labelKey: 'sandbox.field.issueDate', defaultValue: '2019-03-22' },
          { name: 'expiry_date', labelKey: 'sandbox.field.expiryDate', defaultValue: '2034-03-22' },
          { name: 'restrictions', labelKey: 'sandbox.field.restrictions', defaultValue: 'None' },
          { name: 'license_number', labelKey: 'sandbox.field.licenseNumber', defaultValue: 'UA-DL-12345678' },
        ],
        issuer: 'https://hsc.gov.ua',
        country: 'Ukraine',
        flag: ['#005BBB', '#FFD500'],
        flagDir: 'col',
        issuerTitleKey: 'sandbox.issuerTitleDriversUa',
        issuerSubtitleKey: 'sandbox.issuerSubtitleDriversUa',
      },
      eu: {
        fields: [
          { name: 'holder_name', labelKey: 'sandbox.field.holderName', defaultValue: 'Kadri Tamm' },
          { name: 'category', labelKey: 'sandbox.field.category', defaultValue: 'A, B, C1' },
          { name: 'issue_date', labelKey: 'sandbox.field.issueDate', defaultValue: '2019-03-22' },
          { name: 'expiry_date', labelKey: 'sandbox.field.expiryDate', defaultValue: '2034-03-22' },
          { name: 'restrictions', labelKey: 'sandbox.field.restrictions', defaultValue: 'None' },
          { name: 'license_number', labelKey: 'sandbox.field.licenseNumber', defaultValue: 'EE-DL-49301150123' },
        ],
        issuer: 'https://ppa.ee',
        country: 'Estonia',
        flag: ['#0072CE', '#000000', '#FFFFFF'],
        flagDir: 'col',
        issuerTitleKey: 'sandbox.issuerTitleDrivers',
        issuerSubtitleKey: 'sandbox.issuerSubtitleDrivers',
      },
    },
    predicates: [
      { id: 'category_b', labelKey: 'sandbox.predCategoryB', descKey: 'sandbox.predCategoryBDesc', predicate: { claim: 'category', op: 'eq', value: 'A, B, C1' }, defaultChecked: true },
      { id: 'valid', labelKey: 'sandbox.predValid', descKey: 'sandbox.predValidDesc', predicate: { claim: 'expiry_date', op: 'gte', value: isoDateToday() }, defaultChecked: true },
      { id: 'experienced', labelKey: 'sandbox.predExperienced', descKey: 'sandbox.predExperiencedDesc', predicate: { claim: 'issue_date', op: 'lte', value: isoDateYearsAgo(2) }, defaultChecked: false },
      { id: 'no_restrictions', labelKey: 'sandbox.predNoRestrictions', descKey: 'sandbox.predNoRestrictionsDesc', predicate: { claim: 'restrictions', op: 'eq', value: 'None' }, defaultChecked: false },
    ],
  },
  {
    id: 'diploma',
    labelKey: 'sandbox.tabDiploma',
    credLabelKey: 'sandbox.credLabelDiploma',
    variants: {
      ua: {
        fields: [
          { name: 'student_name', labelKey: 'sandbox.field.studentName', defaultValue: 'Дмитро Бондаренко' },
          { name: 'university', labelKey: 'sandbox.field.university', defaultValue: 'КПІ ім. Ігоря Сікорського' },
          { name: 'degree', labelKey: 'sandbox.field.degree', defaultValue: 'Master (M2)' },
          { name: 'field_of_study', labelKey: 'sandbox.field.fieldOfStudy', defaultValue: 'Computer Science' },
          { name: 'graduation_year', labelKey: 'sandbox.field.graduationYear', defaultValue: '2022' },
          { name: 'diploma_number', labelKey: 'sandbox.field.diplomaNumber', defaultValue: 'UA-KPI-2022-07891' },
          { name: 'honors', labelKey: 'sandbox.field.honors', defaultValue: 'Magna Cum Laude' },
        ],
        issuer: 'https://kpi.ua',
        country: 'Ukraine',
        flag: ['#005BBB', '#FFD500'],
        flagDir: 'col',
        issuerTitleKey: 'sandbox.issuerTitleDiplomaUa',
        issuerSubtitleKey: 'sandbox.issuerSubtitleDiplomaUa',
      },
      eu: {
        fields: [
          { name: 'student_name', labelKey: 'sandbox.field.studentName', defaultValue: 'Camille Dubois' },
          { name: 'university', labelKey: 'sandbox.field.university', defaultValue: 'Sorbonne Universit\u00e9' },
          { name: 'degree', labelKey: 'sandbox.field.degree', defaultValue: 'Master (M2)' },
          { name: 'field_of_study', labelKey: 'sandbox.field.fieldOfStudy', defaultValue: 'Computer Science' },
          { name: 'graduation_year', labelKey: 'sandbox.field.graduationYear', defaultValue: '2023' },
          { name: 'diploma_number', labelKey: 'sandbox.field.diplomaNumber', defaultValue: 'FR-SORB-2023-04521' },
          { name: 'honors', labelKey: 'sandbox.field.honors', defaultValue: 'Magna Cum Laude' },
        ],
        issuer: 'https://sorbonne-universite.fr',
        country: 'France',
        flag: ['#002395', '#FFFFFF', '#ED2939'],
        flagDir: 'row',
        issuerTitleKey: 'sandbox.issuerTitleDiploma',
        issuerSubtitleKey: 'sandbox.issuerSubtitleDiploma',
      },
    },
    predicates: [
      { id: 'stem', labelKey: 'sandbox.predStem', descKey: 'sandbox.predStemDesc', predicate: { claim: 'field_of_study', op: 'set_member', value: ['Computer Science', 'Mathematics', 'Physics', 'Chemistry', 'Biology', 'Engineering'] }, defaultChecked: true },
      { id: 'recent_grad', labelKey: 'sandbox.predRecentGrad', descKey: 'sandbox.predRecentGradDesc', predicate: { claim: 'graduation_year', op: 'gte', value: 2020 }, defaultChecked: true },
      { id: 'masters', labelKey: 'sandbox.predMasters', descKey: 'sandbox.predMastersDesc', predicate: { claim: 'degree', op: 'set_member', value: ['Master (M1)', 'Master (M2)', 'PhD'] }, defaultChecked: false },
      { id: 'university_match', labelKey: 'sandbox.predUniversityMatch', descKey: 'sandbox.predUniversityMatchDesc', predicate: { claim: 'university', op: 'eq', value: '__FROM_FORM__' }, defaultChecked: false },
    ],
  },
  {
    id: 'student_id',
    labelKey: 'sandbox.tabStudentId',
    credLabelKey: 'sandbox.credLabelStudentId',
    variants: {
      ua: {
        fields: [
          { name: 'student_name', labelKey: 'sandbox.field.studentName', defaultValue: 'Оксана Шевченко' },
          { name: 'university', labelKey: 'sandbox.field.university', defaultValue: 'КНУ ім. Тараса Шевченка' },
          { name: 'faculty', labelKey: 'sandbox.field.faculty', defaultValue: 'Інформатика' },
          { name: 'enrollment_year', labelKey: 'sandbox.field.enrollmentYear', defaultValue: '2022' },
          { name: 'valid_until', labelKey: 'sandbox.field.validUntil', defaultValue: '2026-09-30' },
          { name: 'student_number', labelKey: 'sandbox.field.studentNumber', defaultValue: 'UA-KNU-STU-21-98765' },
        ],
        issuer: 'https://knu.ua',
        country: 'Ukraine',
        flag: ['#005BBB', '#FFD500'],
        flagDir: 'col',
        issuerTitleKey: 'sandbox.issuerTitleStudentIdUa',
        issuerSubtitleKey: 'sandbox.issuerSubtitleStudentIdUa',
      },
      eu: {
        fields: [
          { name: 'student_name', labelKey: 'sandbox.field.studentName', defaultValue: 'Katarzyna Nowak' },
          { name: 'university', labelKey: 'sandbox.field.university', defaultValue: 'Uniwersytet Warszawski' },
          { name: 'faculty', labelKey: 'sandbox.field.faculty', defaultValue: 'Informatyka' },
          { name: 'enrollment_year', labelKey: 'sandbox.field.enrollmentYear', defaultValue: '2022' },
          { name: 'valid_until', labelKey: 'sandbox.field.validUntil', defaultValue: '2026-09-30' },
          { name: 'student_number', labelKey: 'sandbox.field.studentNumber', defaultValue: 'PL-UW-STU-22-31547' },
        ],
        issuer: 'https://uw.edu.pl',
        country: 'Poland',
        flag: ['#FFFFFF', '#DC143C'],
        flagDir: 'col',
        issuerTitleKey: 'sandbox.issuerTitleStudentId',
        issuerSubtitleKey: 'sandbox.issuerSubtitleStudentId',
      },
    },
    predicates: [
      { id: 'active_student', labelKey: 'sandbox.predActiveStudent', descKey: 'sandbox.predActiveStudentDesc', predicate: { claim: 'valid_until', op: 'gte', value: isoDateToday() }, defaultChecked: true },
      { id: 'enrolled_recently', labelKey: 'sandbox.predEnrolledRecently', descKey: 'sandbox.predEnrolledRecentlyDesc', predicate: { claim: 'enrollment_year', op: 'gte', value: 2020 }, defaultChecked: false },
      { id: 'university_match', labelKey: 'sandbox.predUniversityMatch', descKey: 'sandbox.predUniversityMatchDesc', predicate: { claim: 'university', op: 'eq', value: '__FROM_FORM__' }, defaultChecked: false },
    ],
  },
  {
    id: 'vehicle',
    labelKey: 'sandbox.tabVehicle',
    credLabelKey: 'sandbox.credLabelVehicle',
    variants: {
      ua: {
        fields: [
          { name: 'owner_name', labelKey: 'sandbox.field.ownerName', defaultValue: 'Олександр Петренко' },
          { name: 'owner_document_number', labelKey: 'sandbox.field.ownerDocNumber', defaultValue: 'UA-1234567890' },
          { name: 'plate_number', labelKey: 'sandbox.field.plateNumber', defaultValue: 'AA1234BB' },
          { name: 'make_model', labelKey: 'sandbox.field.makeModel', defaultValue: 'Volkswagen Golf' },
          { name: 'vin', labelKey: 'sandbox.field.vin', defaultValue: 'WVWZZZ3CZWE123456' },
          { name: 'insurance_expiry', labelKey: 'sandbox.field.insuranceExpiry', defaultValue: '2027-01-15' },
          { name: 'registration_date', labelKey: 'sandbox.field.registrationDate', defaultValue: '2021-06-10' },
        ],
        issuer: 'https://mvs.gov.ua',
        country: 'Ukraine',
        flag: ['#005BBB', '#FFD500'],
        flagDir: 'col',
        issuerTitleKey: 'sandbox.issuerTitleVehicleUa',
        issuerSubtitleKey: 'sandbox.issuerSubtitleVehicleUa',
      },
      eu: {
        fields: [
          { name: 'owner_name', labelKey: 'sandbox.field.ownerName', defaultValue: 'Maximilian Schneider' },
          { name: 'owner_document_number', labelKey: 'sandbox.field.ownerDocNumber', defaultValue: 'DE-1234567890' },
          { name: 'plate_number', labelKey: 'sandbox.field.plateNumber', defaultValue: 'B-MS 2847' },
          { name: 'make_model', labelKey: 'sandbox.field.makeModel', defaultValue: 'Volkswagen Golf' },
          { name: 'vin', labelKey: 'sandbox.field.vin', defaultValue: 'WVWZZZ1JZYW000001' },
          { name: 'insurance_expiry', labelKey: 'sandbox.field.insuranceExpiry', defaultValue: '2027-01-15' },
          { name: 'registration_date', labelKey: 'sandbox.field.registrationDate', defaultValue: '2021-06-10' },
        ],
        issuer: 'https://kba.de',
        country: 'Germany',
        flag: ['#000000', '#DD0000', '#FFCC00'],
        flagDir: 'col',
        issuerTitleKey: 'sandbox.issuerTitleVehicle',
        issuerSubtitleKey: 'sandbox.issuerSubtitleVehicle',
      },
    },
    predicates: [
      { id: 'insured', labelKey: 'sandbox.predInsured', descKey: 'sandbox.predInsuredDesc', predicate: { claim: 'insurance_expiry', op: 'gte', value: isoDateToday() }, defaultChecked: true },
      { id: 'eu_type', labelKey: 'sandbox.predEuType', descKey: 'sandbox.predEuTypeDesc', predicate: { claim: 'make_model', op: 'set_member', value: ['Volkswagen Golf', 'BMW 3 Series', 'Toyota Corolla', 'Renault Clio', 'Fiat 500'] }, defaultChecked: true },
      { id: 'vin_active', labelKey: 'sandbox.predVinActive', descKey: 'sandbox.predVinActiveDesc', predicate: { claim: 'vin', op: 'neq', value: 'REVOKED' }, defaultChecked: false },
    ],
  },
]
