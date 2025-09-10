#include <unknwn.h>
#include <oaidl.h>

namespace mscorlib {

struct _Assembly;
struct _AssemblyName;
struct _AssemblyBuilder;
struct _Binder;
struct _ConstructorInfo;
struct _CultureInfo;
struct _CrossAppDomainDelegate;
struct _Delegate;
struct _EventInfo;
struct _EventHandler;
struct _AssemblyLoadEventHandler;
struct _Evidence;
struct _FieldInfo;
struct _FileStream;
struct _MemberFilter;
struct _MethodInfo;
struct _Module;
struct _ModuleResolveEventHandler;
struct _ObjectHandle;
struct _PermissionSet;
struct _PolicyLevel;
struct _PropertyInfo;
struct _ResolveEventHandler;
struct _SerializationInfo;
struct _Stream;
struct _Type;
struct _TypeFilter;
struct _UnhandledExceptionEventHandler;
struct _Version;
struct ICustomAttributeProvider;
struct IPrincipal;

// thanks gemini

enum AssemblyBuilderAccess : int
{
    AssemblyBuilderAccess_Run = 1,
    AssemblyBuilderAccess_Save = 2,
    AssemblyBuilderAccess_RunAndSave = 3,
    AssemblyBuilderAccess_ReflectionOnly = 6,
    AssemblyBuilderAccess_RunAndCollect = 9
};

enum BindingFlags : int
{
    BindingFlags_Default = 0,
    BindingFlags_IgnoreCase = 1,
    BindingFlags_DeclaredOnly = 2,
    BindingFlags_Instance = 4,
    BindingFlags_Static = 8,
    BindingFlags_Public = 16,
    BindingFlags_NonPublic = 32,
    BindingFlags_FlattenHierarchy = 64,
    BindingFlags_InvokeMethod = 256,
    BindingFlags_CreateInstance = 512,
    BindingFlags_GetField = 1024,
    BindingFlags_SetField = 2048,
    BindingFlags_GetProperty = 4096,
    BindingFlags_SetProperty = 8192,
    BindingFlags_PutDispProperty = 16384,
    BindingFlags_PutRefDispProperty = 32768,
    BindingFlags_ExactBinding = 65536,
    BindingFlags_SuppressChangeType = 131072,
    BindingFlags_OptionalParamBinding = 262144,
    BindingFlags_IgnoreReturn = 16777216
};

enum CallingConventions : int
{
    CallingConventions_Standard = 1,
    CallingConventions_VarArgs = 2,
    CallingConventions_Any = 3,
    CallingConventions_HasThis = 32,
    CallingConventions_ExplicitThis = 64
};

enum MemberTypes : int
{
    MemberTypes_Constructor = 1,
    MemberTypes_Event = 2,
    MemberTypes_Field = 4,
    MemberTypes_Method = 8,
    MemberTypes_Property = 16,
    MemberTypes_TypeInfo = 32,
    MemberTypes_Custom = 64,
    MemberTypes_NestedType = 128,
    MemberTypes_All = 191
};

enum MethodAttributes : int
{
    MethodAttributes_MemberAccessMask = 7,
    MethodAttributes_PrivateScope = 0,
    MethodAttributes_Private = 1,
    MethodAttributes_FamANDAssem = 2,
    MethodAttributes_Assembly = 3,
    MethodAttributes_Family = 4,
    MethodAttributes_FamORAssem = 5,
    MethodAttributes_Public = 6,
    MethodAttributes_Static = 16,
    MethodAttributes_Final = 32,
    MethodAttributes_Virtual = 64,
    MethodAttributes_HideBySig = 128,
    MethodAttributes_CheckAccessOnOverride = 512,
    MethodAttributes_VtableLayoutMask = 256,
    MethodAttributes_ReuseSlot = 0,
    MethodAttributes_NewSlot = 256,
    MethodAttributes_Abstract = 1024,
    MethodAttributes_SpecialName = 2048,
    MethodAttributes_PinvokeImpl = 8192,
    MethodAttributes_UnmanagedExport = 8,
    MethodAttributes_RTSpecialName = 4096,
    MethodAttributes_ReservedMask = 53248,
    MethodAttributes_HasSecurity = 16384,
    MethodAttributes_RequireSecObject = 32768
};

enum MethodImplAttributes : int
{
    MethodImplAttributes_CodeTypeMask = 3,
    MethodImplAttributes_IL = 0,
    MethodImplAttributes_Native = 1,
    MethodImplAttributes_OPTIL = 2,
    MethodImplAttributes_Runtime = 3,
    MethodImplAttributes_ManagedMask = 4,
    MethodImplAttributes_Unmanaged = 4,
    MethodImplAttributes_Managed = 0,
    MethodImplAttributes_ForwardRef = 16,
    MethodImplAttributes_PreserveSig = 128,
    MethodImplAttributes_InternalCall = 4096,
    MethodImplAttributes_Synchronized = 32,
    MethodImplAttributes_NoInlining = 8,
    MethodImplAttributes_NoOptimization = 64,
    MethodImplAttributes_MaxMethodImplVal = 65535
};

enum PrincipalPolicy : int
{
    PrincipalPolicy_UnauthenticatedPrincipal = 0,
    PrincipalPolicy_NoPrincipal = 1,
    PrincipalPolicy_WindowsPrincipal = 2
};

enum StreamingContextStates : int
{
    StreamingContextStates_CrossProcess = 1,
    StreamingContextStates_CrossMachine = 2,
    StreamingContextStates_File = 4,
    StreamingContextStates_Persistence = 8,
    StreamingContextStates_Remoting = 16,
    StreamingContextStates_Other = 32,
    StreamingContextStates_Clone = 64,
    StreamingContextStates_CrossAppDomain = 128,
    StreamingContextStates_All = 255
};

enum TypeAttributes : int
{
    TypeAttributes_VisibilityMask = 7,
    TypeAttributes_NotPublic = 0,
    TypeAttributes_Public = 1,
    TypeAttributes_NestedPublic = 2,
    TypeAttributes_NestedPrivate = 3,
    TypeAttributes_NestedFamily = 4,
    TypeAttributes_NestedAssembly = 5,
    TypeAttributes_NestedFamANDAssem = 6,
    TypeAttributes_NestedFamORAssem = 7,
    TypeAttributes_LayoutMask = 24,
    TypeAttributes_AutoLayout = 0,
    TypeAttributes_SequentialLayout = 8,
    TypeAttributes_ExplicitLayout = 16,
    TypeAttributes_ClassSemanticsMask = 32,
    TypeAttributes_Class = 0,
    TypeAttributes_Interface = 32,
    TypeAttributes_Abstract = 128,
    TypeAttributes_Sealed = 256,
    TypeAttributes_SpecialName = 1024,
    TypeAttributes_Import = 4096,
    TypeAttributes_Serializable = 8192,
    TypeAttributes_StringFormatMask = 196608,
    TypeAttributes_AnsiClass = 0,
    TypeAttributes_UnicodeClass = 65536,
    TypeAttributes_AutoClass = 131072,
    TypeAttributes_CustomFormatClass = 196608,
    TypeAttributes_CustomFormatMask = 12582912,
    TypeAttributes_BeforeFieldInit = 1048576,
    TypeAttributes_ReservedMask = 264192,
    TypeAttributes_RTSpecialName = 2048,
    TypeAttributes_HasSecurity = 262144,
};


struct StreamingContext
{
    VARIANT m_additionalContext;
    enum StreamingContextStates m_state;
};

struct RuntimeMethodHandle
{
    IUnknown* m_value;
};

struct RuntimeTypeHandle
{
    IUnknown* m_type;
};

struct InterfaceMapping
{
    struct _Type* TargetType;
    struct _Type* interfaceType;
    SAFEARRAY* TargetMethods;
    SAFEARRAY* InterfaceMethods;
};

//COM AppDomain methods

struct __declspec(uuid("05f696dc-2b29-3663-ad8b-c4389cf2a713"))
_AppDomain : IUnknown
{
    // IDispatch methods
    virtual HRESULT __stdcall GetTypeInfoCount(unsigned long* pcTInfo) = 0;
    virtual HRESULT __stdcall GetTypeInfo(unsigned long iTInfo, unsigned long lcid, void** ppTInfo) = 0;
    virtual HRESULT __stdcall GetIDsOfNames(GUID* riid, wchar_t** rgszNames, unsigned long cNames, unsigned long lcid, long* rgDispId) = 0;
    virtual HRESULT __stdcall Invoke(long dispIdMember, GUID* riid, unsigned long lcid, short wFlags, DISPPARAMS* pDispParams, VARIANT* pVarResult, EXCEPINFO* pExcepInfo, unsigned long* puArgErr) = 0;

    // _AppDomain methods
    virtual HRESULT __stdcall get_ToString(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall Equals(VARIANT other, VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall GetHashCode(long* pRetVal) = 0;
    virtual HRESULT __stdcall GetType(struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall InitializeLifetimeService(VARIANT* pRetVal) = 0;
    virtual HRESULT __stdcall GetLifetimeService(VARIANT* pRetVal) = 0;
    virtual HRESULT __stdcall get_Evidence(struct _Evidence** pRetVal) = 0;
    virtual HRESULT __stdcall add_DomainUnload(struct _EventHandler* value) = 0;
    virtual HRESULT __stdcall remove_DomainUnload(struct _EventHandler* value) = 0;
    virtual HRESULT __stdcall add_AssemblyLoad(struct _AssemblyLoadEventHandler* value) = 0;
    virtual HRESULT __stdcall remove_AssemblyLoad(struct _AssemblyLoadEventHandler* value) = 0;
    virtual HRESULT __stdcall add_ProcessExit(struct _EventHandler* value) = 0;
    virtual HRESULT __stdcall remove_ProcessExit(struct _EventHandler* value) = 0;
    virtual HRESULT __stdcall add_TypeResolve(struct _ResolveEventHandler* value) = 0;
    virtual HRESULT __stdcall remove_TypeResolve(struct _ResolveEventHandler* value) = 0;
    virtual HRESULT __stdcall add_ResourceResolve(struct _ResolveEventHandler* value) = 0;
    virtual HRESULT __stdcall remove_ResourceResolve(struct _ResolveEventHandler* value) = 0;
    virtual HRESULT __stdcall add_AssemblyResolve(struct _ResolveEventHandler* value) = 0;
    virtual HRESULT __stdcall remove_AssemblyResolve(struct _ResolveEventHandler* value) = 0;
    virtual HRESULT __stdcall add_UnhandledException(struct _UnhandledExceptionEventHandler* value) = 0;
    virtual HRESULT __stdcall remove_UnhandledException(struct _UnhandledExceptionEventHandler* value) = 0;
    virtual HRESULT __stdcall DefineDynamicAssembly(struct _AssemblyName* name, enum AssemblyBuilderAccess access, struct _AssemblyBuilder** pRetVal) = 0;
    virtual HRESULT __stdcall DefineDynamicAssembly_2(struct _AssemblyName* name, enum AssemblyBuilderAccess access, BSTR dir, struct _AssemblyBuilder** pRetVal) = 0;
    virtual HRESULT __stdcall DefineDynamicAssembly_3(struct _AssemblyName* name, enum AssemblyBuilderAccess access, struct _Evidence* Evidence, struct _AssemblyBuilder** pRetVal) = 0;
    virtual HRESULT __stdcall DefineDynamicAssembly_4(struct _AssemblyName* name, enum AssemblyBuilderAccess access, struct _PermissionSet* requiredPermissions, struct _PermissionSet* optionalPermissions, struct _PermissionSet* refusedPermissions, struct _AssemblyBuilder** pRetVal) = 0;
    virtual HRESULT __stdcall DefineDynamicAssembly_5(struct _AssemblyName* name, enum AssemblyBuilderAccess access, BSTR dir, struct _Evidence* Evidence, struct _AssemblyBuilder** pRetVal) = 0;
    virtual HRESULT __stdcall DefineDynamicAssembly_6(struct _AssemblyName* name, enum AssemblyBuilderAccess access, BSTR dir, struct _PermissionSet* requiredPermissions, struct _PermissionSet* optionalPermissions, struct _PermissionSet* refusedPermissions, struct _AssemblyBuilder** pRetVal) = 0;
    virtual HRESULT __stdcall DefineDynamicAssembly_7(struct _AssemblyName* name, enum AssemblyBuilderAccess access, struct _Evidence* Evidence, struct _PermissionSet* requiredPermissions, struct _PermissionSet* optionalPermissions, struct _PermissionSet* refusedPermissions, struct _AssemblyBuilder** pRetVal) = 0;
    virtual HRESULT __stdcall DefineDynamicAssembly_8(struct _AssemblyName* name, enum AssemblyBuilderAccess access, BSTR dir, struct _Evidence* Evidence, struct _PermissionSet* requiredPermissions, struct _PermissionSet* optionalPermissions, struct _PermissionSet* refusedPermissions, struct _AssemblyBuilder** pRetVal) = 0;
    virtual HRESULT __stdcall DefineDynamicAssembly_9(struct _AssemblyName* name, enum AssemblyBuilderAccess access, BSTR dir, struct _Evidence* Evidence, struct _PermissionSet* requiredPermissions, struct _PermissionSet* optionalPermissions, struct _PermissionSet* refusedPermissions, VARIANT_BOOL IsSynchronized, struct _AssemblyBuilder** pRetVal) = 0;
    virtual HRESULT __stdcall CreateInstance(BSTR AssemblyName, BSTR typeName, struct _ObjectHandle** pRetVal) = 0;
    virtual HRESULT __stdcall CreateInstanceFrom(BSTR assemblyFile, BSTR typeName, struct _ObjectHandle** pRetVal) = 0;
    virtual HRESULT __stdcall CreateInstance_2(BSTR AssemblyName, BSTR typeName, SAFEARRAY* activationAttributes, struct _ObjectHandle** pRetVal) = 0;
    virtual HRESULT __stdcall CreateInstanceFrom_2(BSTR assemblyFile, BSTR typeName, SAFEARRAY* activationAttributes, struct _ObjectHandle** pRetVal) = 0;
    virtual HRESULT __stdcall CreateInstance_3(BSTR AssemblyName, BSTR typeName, VARIANT_BOOL ignoreCase, enum BindingFlags bindingAttr, struct _Binder* Binder, SAFEARRAY* args, struct _CultureInfo* culture, SAFEARRAY* activationAttributes, struct _Evidence* securityAttributes, struct _ObjectHandle** pRetVal) = 0;
    virtual HRESULT __stdcall CreateInstanceFrom_3(BSTR assemblyFile, BSTR typeName, VARIANT_BOOL ignoreCase, enum BindingFlags bindingAttr, struct _Binder* Binder, SAFEARRAY* args, struct _CultureInfo* culture, SAFEARRAY* activationAttributes, struct _Evidence* securityAttributes, struct _ObjectHandle** pRetVal) = 0;
    virtual HRESULT __stdcall Load(struct _AssemblyName* assemblyRef, struct _Assembly** pRetVal) = 0;
    virtual HRESULT __stdcall Load_2(BSTR assemblyString, struct _Assembly** pRetVal) = 0;
    virtual HRESULT __stdcall Load_3(SAFEARRAY* rawAssembly, struct _Assembly** pRetVal) = 0;
   /*
    virtual HRESULT __stdcall Load_4(SAFEARRAY* rawAssembly, SAFEARRAY* rawSymbolStore, struct _Assembly** pRetVal) = 0;
    virtual HRESULT __stdcall Load_5(SAFEARRAY* rawAssembly, SAFEARRAY* rawSymbolStore, struct _Evidence* securityEvidence, struct _Assembly** pRetVal) = 0;
    virtual HRESULT __stdcall Load_6(struct _AssemblyName* assemblyRef, struct _Evidence* assemblySecurity, struct _Assembly** pRetVal) = 0;
    virtual HRESULT __stdcall Load_7(BSTR assemblyString, struct _Evidence* assemblySecurity, struct _Assembly** pRetVal) = 0;
    virtual HRESULT __stdcall ExecuteAssembly(BSTR assemblyFile, struct _Evidence* assemblySecurity, long* pRetVal) = 0;
    virtual HRESULT __stdcall ExecuteAssembly_2(BSTR assemblyFile, long* pRetVal) = 0;
    virtual HRESULT __stdcall ExecuteAssembly_3(BSTR assemblyFile, struct _Evidence* assemblySecurity, SAFEARRAY* args, long* pRetVal) = 0;
    virtual HRESULT __stdcall get_FriendlyName(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall get_BaseDirectory(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall get_RelativeSearchPath(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall get_ShadowCopyFiles(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall GetAssemblies(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall AppendPrivatePath(BSTR Path) = 0;
    virtual HRESULT __stdcall ClearPrivatePath() = 0;
    virtual HRESULT __stdcall SetShadowCopyPath(BSTR s) = 0;
    virtual HRESULT __stdcall ClearShadowCopyPath() = 0;
    virtual HRESULT __stdcall SetCachePath(BSTR s) = 0;
    virtual HRESULT __stdcall SetData(BSTR name, VARIANT data) = 0;
    virtual HRESULT __stdcall GetData(BSTR name, VARIANT* pRetVal) = 0;
    virtual HRESULT __stdcall SetAppDomainPolicy(struct _PolicyLevel* domainPolicy) = 0;
    virtual HRESULT __stdcall SetThreadPrincipal(struct IPrincipal* principal) = 0;
    virtual HRESULT __stdcall SetPrincipalPolicy(enum PrincipalPolicy policy) = 0;
    virtual HRESULT __stdcall DoCallBack(struct _CrossAppDomainDelegate* theDelegate) = 0;
    virtual HRESULT __stdcall get_DynamicDirectory(BSTR* pRetVal) = 0;
    */
};

//COM Assembly definitions

struct __declspec(uuid("17156360-2f1a-384a-bc52-fde93c215c5b"))
_Assembly : IDispatch
{
    virtual HRESULT __stdcall get_ToString(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall Equals(VARIANT other, VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall GetHashCode(long* pRetVal) = 0;
    virtual HRESULT __stdcall GetType(struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall get_CodeBase(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall get_EscapedCodeBase(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall GetName(struct _AssemblyName** pRetVal) = 0;
    virtual HRESULT __stdcall GetName_2(VARIANT_BOOL copiedName, struct _AssemblyName** pRetVal) = 0;
    virtual HRESULT __stdcall get_FullName(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall get_EntryPoint(struct _MethodInfo** pRetVal) = 0;
    /*
    virtual HRESULT __stdcall GetType_2(BSTR name, struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall GetType_3(BSTR name, VARIANT_BOOL throwOnError, struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall GetExportedTypes(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetTypes(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetManifestResourceStream(struct _Type* Type, BSTR name, struct _Stream** pRetVal) = 0;
    virtual HRESULT __stdcall GetManifestResourceStream_2(BSTR name, struct _Stream** pRetVal) = 0;
    virtual HRESULT __stdcall GetFile(BSTR name, struct _FileStream** pRetVal) = 0;
    virtual HRESULT __stdcall GetFiles(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetFiles_2(VARIANT_BOOL getResourceModules, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetManifestResourceNames(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetManifestResourceInfo(BSTR resourceName, struct _ManifestResourceInfo** pRetVal) = 0;
    virtual HRESULT __stdcall get_Location(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall get_Evidence(struct _Evidence** pRetVal) = 0;
    virtual HRESULT __stdcall GetCustomAttributes(struct _Type* attributeType, VARIANT_BOOL inherit, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetCustomAttributes_2(VARIANT_BOOL inherit, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall IsDefined(struct _Type* attributeType, VARIANT_BOOL inherit, VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall GetObjectData(struct _SerializationInfo* info, struct StreamingContext Context) = 0;
    virtual HRESULT __stdcall add_ModuleResolve(struct _ModuleResolveEventHandler* value) = 0;
    virtual HRESULT __stdcall remove_ModuleResolve(struct _ModuleResolveEventHandler* value) = 0;
    virtual HRESULT __stdcall GetType_4(BSTR name, VARIANT_BOOL throwOnError, VARIANT_BOOL ignoreCase, struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall GetSatelliteAssembly(struct _CultureInfo* culture, struct _Assembly** pRetVal) = 0;
    virtual HRESULT __stdcall GetSatelliteAssembly_2(struct _CultureInfo* culture, struct _Version* Version, struct _Assembly** pRetVal) = 0;
    virtual HRESULT __stdcall LoadModule(BSTR moduleName, SAFEARRAY* rawModule, struct _Module** pRetVal) = 0;
    virtual HRESULT __stdcall LoadModule_2(BSTR moduleName, SAFEARRAY* rawModule, SAFEARRAY* rawSymbolStore, struct _Module** pRetVal) = 0;
    virtual HRESULT __stdcall CreateInstance(BSTR typeName, VARIANT* pRetVal) = 0;
    virtual HRESULT __stdcall CreateInstance_2(BSTR typeName, VARIANT_BOOL ignoreCase, VARIANT* pRetVal) = 0;
    virtual HRESULT __stdcall CreateInstance_3(BSTR typeName, VARIANT_BOOL ignoreCase, enum BindingFlags bindingAttr, struct _Binder* Binder, SAFEARRAY* args, struct _CultureInfo* culture, SAFEARRAY* activationAttributes, VARIANT* pRetVal) = 0;
    virtual HRESULT __stdcall GetLoadedModules(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetLoadedModules_2(VARIANT_BOOL getResourceModules, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetModules(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetModules_2(VARIANT_BOOL getResourceModules, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetModule(BSTR name, struct _Module** pRetVal) = 0;
    virtual HRESULT __stdcall GetReferencedAssemblies(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall get_GlobalAssemblyCache(VARIANT_BOOL* pRetVal) = 0;
    */
};

//Type shit

struct __declspec(uuid("bca8b44d-aad6-3a86-8ab7-03349f4f2da2"))
_Type : IUnknown
{
    // IDispatch methods
    virtual HRESULT __stdcall GetTypeInfoCount(unsigned long* pcTInfo) = 0;
    virtual HRESULT __stdcall GetTypeInfo(unsigned long iTInfo, unsigned long lcid, void** ppTInfo) = 0;
    virtual HRESULT __stdcall GetIDsOfNames(GUID* riid, wchar_t** rgszNames, unsigned long cNames, unsigned long lcid, long* rgDispId) = 0;
    virtual HRESULT __stdcall Invoke(long dispIdMember, GUID* riid, unsigned long lcid, short wFlags, DISPPARAMS* pDispParams, VARIANT* pVarResult, EXCEPINFO* pExcepInfo, unsigned long* puArgErr) = 0;

    // _Type methods
    virtual HRESULT __stdcall get_ToString(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall Equals(VARIANT other, VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall GetHashCode(long* pRetVal) = 0;
    virtual HRESULT __stdcall GetType(struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall get_MemberType(enum MemberTypes* pRetVal) = 0;
    virtual HRESULT __stdcall get_name(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall get_DeclaringType(struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall get_ReflectedType(struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall GetCustomAttributes(struct _Type* attributeType, VARIANT_BOOL inherit, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetCustomAttributes_2(VARIANT_BOOL inherit, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall IsDefined(struct _Type* attributeType, VARIANT_BOOL inherit, VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_Guid(GUID* pRetVal) = 0;
    virtual HRESULT __stdcall get_Module(struct _Module** pRetVal) = 0;
    virtual HRESULT __stdcall get_Assembly(struct _Assembly** pRetVal) = 0;
    virtual HRESULT __stdcall get_TypeHandle(struct RuntimeTypeHandle* pRetVal) = 0;
    virtual HRESULT __stdcall get_FullName(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall get_Namespace(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall get_AssemblyQualifiedName(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall GetArrayRank(long* pRetVal) = 0;
    virtual HRESULT __stdcall get_BaseType(struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall GetConstructors(enum BindingFlags bindingAttr, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetInterface(BSTR name, VARIANT_BOOL ignoreCase, struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall GetInterfaces(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall FindInterfaces(struct _TypeFilter* filter, VARIANT filterCriteria, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetEvent(BSTR name, enum BindingFlags bindingAttr, struct _EventInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetEvents(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetEvents_2(enum BindingFlags bindingAttr, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetNestedTypes(enum BindingFlags bindingAttr, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetNestedType(BSTR name, enum BindingFlags bindingAttr, struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall GetMember(BSTR name, enum MemberTypes Type, enum BindingFlags bindingAttr, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetDefaultMembers(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall FindMembers(enum MemberTypes MemberType, enum BindingFlags bindingAttr, struct _MemberFilter* filter, VARIANT filterCriteria, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetElementType(struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall IsSubclassOf(struct _Type* c, VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall IsInstanceOfType(VARIANT o, VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall IsAssignableFrom(struct _Type* c, VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall GetInterfaceMap(struct _Type* interfaceType, struct InterfaceMapping* pRetVal) = 0;
    virtual HRESULT __stdcall GetMethod(BSTR name, enum BindingFlags bindingAttr, struct _Binder* Binder, SAFEARRAY* types, SAFEARRAY* modifiers, struct _MethodInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetMethod_2(BSTR name, enum BindingFlags bindingAttr, struct _MethodInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetMethods(enum BindingFlags bindingAttr, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetField(BSTR name, enum BindingFlags bindingAttr, struct _FieldInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetFields(enum BindingFlags bindingAttr, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetProperty(BSTR name, enum BindingFlags bindingAttr, struct _PropertyInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetProperty_2(BSTR name, enum BindingFlags bindingAttr, struct _Binder* Binder, struct _Type* returnType, SAFEARRAY* types, SAFEARRAY* modifiers, struct _PropertyInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetProperties(enum BindingFlags bindingAttr, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetMember_2(BSTR name, enum BindingFlags bindingAttr, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetMembers(enum BindingFlags bindingAttr, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall InvokeMember(BSTR name, enum BindingFlags invokeAttr, struct _Binder* Binder, VARIANT Target, SAFEARRAY* args, SAFEARRAY* modifiers, struct _CultureInfo* culture, SAFEARRAY* namedParameters, VARIANT* pRetVal) = 0;
    virtual HRESULT __stdcall get_UnderlyingSystemType(struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall InvokeMember_2(BSTR name, enum BindingFlags invokeAttr, struct _Binder* Binder, VARIANT Target, SAFEARRAY* args, struct _CultureInfo* culture, VARIANT* pRetVal) = 0;
    virtual HRESULT __stdcall InvokeMember_3(BSTR name, enum BindingFlags invokeAttr, struct _Binder* Binder, VARIANT Target, SAFEARRAY* args, VARIANT* pRetVal) = 0;
    virtual HRESULT __stdcall GetConstructor(enum BindingFlags bindingAttr, struct _Binder* Binder, enum CallingConventions callConvention, SAFEARRAY* types, SAFEARRAY* modifiers, struct _ConstructorInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetConstructor_2(enum BindingFlags bindingAttr, struct _Binder* Binder, SAFEARRAY* types, SAFEARRAY* modifiers, struct _ConstructorInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetConstructor_3(SAFEARRAY* types, struct _ConstructorInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetConstructors_2(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall get_TypeInitializer(struct _ConstructorInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetMethod_3(BSTR name, enum BindingFlags bindingAttr, struct _Binder* Binder, enum CallingConventions callConvention, SAFEARRAY* types, SAFEARRAY* modifiers, struct _MethodInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetMethod_4(BSTR name, SAFEARRAY* types, SAFEARRAY* modifiers, struct _MethodInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetMethod_5(BSTR name, SAFEARRAY* types, struct _MethodInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetMethod_6(BSTR name, struct _MethodInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetMethods_2(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetField_2(BSTR name, struct _FieldInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetFields_2(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetInterface_2(BSTR name, struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall GetEvent_2(BSTR name, struct _EventInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetProperty_3(BSTR name, struct _Type* returnType, SAFEARRAY* types, SAFEARRAY* modifiers, struct _PropertyInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetProperty_4(BSTR name, struct _Type* returnType, SAFEARRAY* types, struct _PropertyInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetProperty_5(BSTR name, SAFEARRAY* types, struct _PropertyInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetProperty_6(BSTR name, struct _Type* returnType, struct _PropertyInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetProperty_7(BSTR name, struct _PropertyInfo** pRetVal) = 0;
    virtual HRESULT __stdcall GetProperties_2(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetNestedTypes_2(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetNestedType_2(BSTR name, struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall GetMember_3(BSTR name, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetMembers_2(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall get_Attributes(enum TypeAttributes* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsNotPublic(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsPublic(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsNestedPublic(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsNestedPrivate(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsNestedFamily(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsNestedAssembly(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsNestedFamANDAssem(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsNestedFamORAssem(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsAutoLayout(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsLayoutSequential(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsExplicitLayout(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsClass(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsInterface(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsValueType(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsAbstract(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsSealed(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsEnum(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsSpecialName(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsImport(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsSerializable(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsAnsiClass(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsUnicodeClass(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsAutoClass(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsArray(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsByRef(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsPointer(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsPrimitive(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsCOMObject(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_HasElementType(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsContextful(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsMarshalByRef(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall Equals_2(struct _Type* o, VARIANT_BOOL* pRetVal) = 0;
};

//MethodInfo interface

struct __declspec(uuid("ffcc1b5d-ecb8-38dd-9b01-3dc8abc2aa5f"))
_MethodInfo : IUnknown
{
    // IDispatch methods
    virtual HRESULT __stdcall GetTypeInfoCount(unsigned long* pcTInfo) = 0;
    virtual HRESULT __stdcall GetTypeInfo(unsigned long iTInfo, unsigned long lcid, void** ppTInfo) = 0;
    virtual HRESULT __stdcall GetIDsOfNames(GUID* riid, wchar_t** rgszNames, unsigned long cNames, unsigned long lcid, long* rgDispId) = 0;
    virtual HRESULT __stdcall Invoke(long dispIdMember, GUID* riid, unsigned long lcid, short wFlags, DISPPARAMS* pDispParams, VARIANT* pVarResult, EXCEPINFO* pExcepInfo, unsigned long* puArgErr) = 0;

    // _MethodInfo methods
    virtual HRESULT __stdcall get_ToString(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall Equals(VARIANT other, VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall GetHashCode(long* pRetVal) = 0;
    virtual HRESULT __stdcall GetType(struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall get_MemberType(enum MemberTypes* pRetVal) = 0;
    virtual HRESULT __stdcall get_name(BSTR* pRetVal) = 0;
    virtual HRESULT __stdcall get_DeclaringType(struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall get_ReflectedType(struct _Type** pRetVal) = 0;
    virtual HRESULT __stdcall GetCustomAttributes(struct _Type* attributeType, VARIANT_BOOL inherit, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetCustomAttributes_2(VARIANT_BOOL inherit, SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall IsDefined(struct _Type* attributeType, VARIANT_BOOL inherit, VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall GetParameters(SAFEARRAY** pRetVal) = 0;
    virtual HRESULT __stdcall GetMethodImplementationFlags(enum MethodImplAttributes* pRetVal) = 0;
    virtual HRESULT __stdcall get_MethodHandle(struct RuntimeMethodHandle* pRetVal) = 0;
    virtual HRESULT __stdcall get_Attributes(enum MethodAttributes* pRetVal) = 0;
    virtual HRESULT __stdcall get_CallingConvention(enum CallingConventions* pRetVal) = 0;
    virtual HRESULT __stdcall Invoke_2(VARIANT obj, enum BindingFlags invokeAttr, struct _Binder* Binder, SAFEARRAY* parameters, struct _CultureInfo* culture, VARIANT* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsPublic(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsPrivate(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsFamily(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsAssembly(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsFamilyAndAssembly(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsFamilyOrAssembly(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsStatic(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsFinal(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsVirtual(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsHideBySig(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsAbstract(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsSpecialName(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall get_IsConstructor(VARIANT_BOOL* pRetVal) = 0;
    virtual HRESULT __stdcall Invoke_3(VARIANT obj, SAFEARRAY* parameters, VARIANT* pRetVal) = 0;
    //virtual HRESULT __stdcall get_returnType(struct _Type** pRetVal) = 0;
    //virtual HRESULT __stdcall get_ReturnTypeCustomAttributes(struct ICustomAttributeProvider** pRetVal) = 0;
    //virtual HRESULT __stdcall GetBaseDefinition(struct _MethodInfo** pRetVal) = 0;
};
}
