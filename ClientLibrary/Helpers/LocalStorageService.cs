
using Blazored.LocalStorage;

namespace ClientLibrary.Helpers
{
    public class LocalStorageService(ILocalStorageService localStorageService)
    {
        private const string StorageKey = "authentication-tokent";
        public async Task<string> GetToken() => await localStorageService.GetItemAsync<string>(StorageKey);
        public async Task SetToken(string item) => await localStorageService.SetItemAsync(StorageKey, item);
        public async Task RemoveToken() => await localStorageService.RemoveItemAsync(StorageKey);
    }
}
